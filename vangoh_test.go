package vangoh

import (
	"bytes"
	"crypto"
	_ "crypto/SHA1"
	"errors"
	"fmt"
	"hash"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"unsafe"
)

func checkAlgorithm(vg *Vangoh, algo func() hash.Hash) bool {
	vga := fmt.Sprintf("%T", vg.algorithm())
	toCheck := fmt.Sprintf("%T", algo())

	return vga == toCheck
}

func assertNilError(t *testing.T, a *AuthenticationError) {
	if a != nil {
		t.Errorf("Expected no error, instead received HTTP %d: %s", a.StatusCode(), a)
		t.FailNow()
	}
}
func assertError(t *testing.T, a *AuthenticationError, e *AuthenticationError) {
	if a == nil {
		t.Errorf("Expected an error with HTTP Status %d, but received no error", e.StatusCode())
		t.FailNow()
	}
	if a != e {
		t.Errorf(
			"Expected an error with status HTTP %d, message '%s', but received HTTP %d, message '%s'", a.StatusCode(), a, e.StatusCode(), e)
		t.FailNow()
	}
}

type testProvider struct {
	promptErr bool
	key       []byte
	secret    []byte
}

func (tp *testProvider) GetSecret(key []byte) ([]byte, error) {
	if tp.promptErr {
		return nil, errors.New("testing error")
	}
	if !bytes.Equal(tp.key, key) {
		return nil, nil
	}
	return tp.secret, nil
}

type testCallbackProvider struct {
	promptErr bool
	key       []byte
	secret    []byte
	modifyPtr bool
	T         *testing.T
}

type testCallbackData struct{ Value string }

var testCallbackValue = "testcallbackvalue"

func (tcp *testCallbackProvider) GetSecret(key []byte, voidPtr *unsafe.Pointer) ([]byte, error) {
	if tcp.promptErr {
		return nil, errors.New("testing error")
	}
	if !bytes.Equal(tcp.key, key) {
		return nil, nil
	}
	if *voidPtr != nil {
		tcp.T.Error("Expected to be passed a pointer to nil.")
		tcp.T.FailNow()
	}
	if tcp.modifyPtr {
		data := &testCallbackData{Value: testCallbackValue}
		*voidPtr = unsafe.Pointer(data)
	}
	return tcp.secret, nil
}

func (tcp *testCallbackProvider) SuccessCallback(r *http.Request, voidPtr *unsafe.Pointer) {
	if tcp.modifyPtr && voidPtr == nil {
		tcp.T.Error("Expected to be passed a valid pointer.")
		tcp.T.FailNow()
	}
	if !tcp.modifyPtr && voidPtr != nil {
		tcp.T.Error("Expected to be passed a nil pointer.")
		tcp.T.FailNow()
	}
	if voidPtr != nil {
		data := (*testCallbackData)(*voidPtr)
		if data.Value != testCallbackValue {
			tcp.T.Error("Expected to unpack the test callback value.")
			tcp.T.FailNow()
		}
	}
}

var tp1 = &testProvider{
	promptErr: false,
	key:       []byte("testIDOne"),
	secret:    []byte("secretOne"),
}

var tp2 = &testProvider{
	promptErr: false,
	key:       []byte("testIDTwo"),
	secret:    []byte("secretTwo"),
}

var tpErr = &testProvider{
	promptErr: true,
	key:       []byte("testIDErr"),
	secret:    []byte("secretErr"),
}

var awsExampleProvider = &testProvider{
	promptErr: false,
	key:       []byte("AKIAIOSFODNN7EXAMPLE"),
	secret:    []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
}

func TestNew(t *testing.T) {
	vg := New()

	if vg.includedHeaders == nil {
		t.Error("includeHeaders not properly intialized")
	}
	if vg.providersByOrg == nil {
		t.Error("providersByOrg not properly intialized")
	}
	if vg.singleProvider != nil {
		t.Error("default constructor should not create a single provider instance")
	}
	if !checkAlgorithm(vg, crypto.SHA256.New) {
		t.Error("default constructor should instantiate the algorithm to SHA256")
	}
}

func TestNewSingleProvider(t *testing.T) {
	vg := NewSingleProvider(tp1)

	if vg.includedHeaders == nil {
		t.Error("includeHeaders not properly intialized")
	}
	if vg.providersByOrg == nil {
		t.Error("providersByOrg not properly intialized")
	}
	if vg.singleProvider == nil {
		t.Error("singleProvider constructor should create a single provider instance")
	}
}

func TestAddProvider(t *testing.T) {
	vg := New()

	if len(vg.providersByOrg) != 0 {
		t.Error("Wrong number of key providers in the Vangoh instance")
	}

	err := vg.AddProvider("test", tp1)
	if err != nil {
		t.Error("Should not have encountered error when adding a new provider")
	}

	if len(vg.providersByOrg) != 1 {
		t.Error("Wrong number of key providers in the Vangoh instance")
	}

	err = vg.AddProvider("test", tp2)
	if err == nil {
		t.Error("Should error when trying to add multiple providers for same org tag")
	}

	if len(vg.providersByOrg) != 1 {
		t.Error("Wrong number of key providers in the Vangoh instance")
	}

	err = vg.AddProvider("notTest", tp2)
	if err != nil {
		t.Error("Should not error when trying to add multiple providers for different org tags")
	}

	if len(vg.providersByOrg) != 2 {
		t.Error("Wrong number of key providers in the Vangoh instance")
	}

	spvg := NewSingleProvider(tp1)
	if len(spvg.providersByOrg) != 0 {
		t.Error("Wrong number of key providers in the Vangoh instance")
	}

	err = spvg.AddProvider("test", tp2)
	if err == nil {
		t.Error("Should error when trying to add second provider to single provider instance")
	}
	if len(spvg.providersByOrg) != 0 {
		t.Error("Wrong number of key providers in the Vangoh instance")
	}
}

func TestAlgorithm(t *testing.T) {
	vg := New()

	if !checkAlgorithm(vg, crypto.SHA256.New) {
		t.Error("default constructor should instantiate the algorithm to SHA256")
	}

	vg.SetAlgorithm(crypto.SHA1.New)
	if !checkAlgorithm(vg, crypto.SHA1.New) {
		t.Error("Algorithm not correctly updated with SetAlgorithm method")
	}
}

func TestAuthHeaderMissingFails(t *testing.T) {
	vg := NewSingleProvider(awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)

	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)

	AddDateHeader(req)
	// No authorizaiton header is added.

	authErr := vg.AuthenticateRequest(req)
	assertError(t, authErr, ErrorAuthHeaderMissing)
}
func TestAuthHeaderMalformedFails(t *testing.T) {
	vg := NewSingleProvider(awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)

	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)

	AddDateHeader(req)
	// Add malformed header.
	req.Header.Set("Authorization", "wooo ORG KEY:SECRET")

	authErr := vg.AuthenticateRequest(req)
	assertError(t, authErr, ErrorAuthHeaderMalformed)
}

func TestProviderWithErrorFails(t *testing.T) {
	vg := NewSingleProvider(tpErr)
	vg.SetAlgorithm(crypto.SHA1.New)

	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)

	AddDateHeader(req)
	AddAuthorizationHeader(vg, req, awsExampleProvider.secret)

	authErr := vg.AuthenticateRequest(req)
	assertError(t, authErr, ErrorInProviderKeyLookup)
}

func TestCallbackProviderWithErrorFails(t *testing.T) {
	var tcpErr = &testCallbackProvider{
		promptErr: true,
		key:       []byte("AKIAIOSFODNN7EXAMPLE"),
		secret:    []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
		modifyPtr: true,
		T:         t,
	}
	vg := NewSingleProvider(tcpErr)
	vg.SetAlgorithm(crypto.SHA1.New)

	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)

	AddDateHeader(req)
	AddAuthorizationHeader(vg, req, awsExampleProvider.secret)

	authErr := vg.AuthenticateRequest(req)
	assertError(t, authErr, ErrorInProviderKeyLookup)
}

func TestCallbackProviderMissingSecret(t *testing.T) {
	var tcp = &testCallbackProvider{
		promptErr: false,
		key:       []byte("NOTTHERIGHTKEY"),
		secret:    []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
		modifyPtr: true,
		T:         t,
	}
	vg := NewSingleProvider(tcp)
	vg.SetAlgorithm(crypto.SHA1.New)

	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)

	AddDateHeader(req)
	AddAuthorizationHeader(vg, req, awsExampleProvider.secret)

	authErr := vg.AuthenticateRequest(req)
	assertError(t, authErr, ErrorSecretNotFound)
}

func TestCallbackProviderSucceedsWithoutModifyingPtr(t *testing.T) {
	var tcp = &testCallbackProvider{
		promptErr: false,
		key:       []byte("AKIAIOSFODNN7EXAMPLE"),
		secret:    []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
		modifyPtr: false,
		T:         t,
	}
	vg := NewSingleProvider(tcp)
	vg.SetAlgorithm(crypto.SHA1.New)

	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)

	AddDateHeader(req)
	AddAuthorizationHeader(vg, req, awsExampleProvider.secret)

	authErr := vg.AuthenticateRequest(req)
	assertNilError(t, authErr)
}

func TestCallbackProviderSucceeds(t *testing.T) {
	var tcp = &testCallbackProvider{
		promptErr: false,
		key:       []byte("AKIAIOSFODNN7EXAMPLE"),
		secret:    []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
		modifyPtr: true,
		T:         t,
	}
	vg := NewSingleProvider(tcp)
	vg.SetAlgorithm(crypto.SHA1.New)

	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)

	AddDateHeader(req)
	AddAuthorizationHeader(vg, req, awsExampleProvider.secret)

	authErr := vg.AuthenticateRequest(req)
	assertNilError(t, authErr)
}

func TestMissingProviderFails(t *testing.T) {
	vg := New()
	vg.SetAlgorithm(crypto.SHA1.New)

	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)

	AddDateHeader(req)
	AddAuthorizationHeader(vg, req, awsExampleProvider.secret)

	authErr := vg.AuthenticateRequest(req)
	assertError(t, authErr, ErrorAuthOrgUnknown)
}
func TestNonSingleProviderSucceeds(t *testing.T) {
	vg := New()
	vg.AddProvider("AWS", awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)

	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)

	AddDateHeader(req)
	AddAuthorizationHeader(vg, req, awsExampleProvider.secret)

	authErr := vg.AuthenticateRequest(req)
	assertNilError(t, authErr)
}

func TestGetSucceedsWithCorrectSignature(t *testing.T) {
	vg := NewSingleProvider(awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)

	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)

	AddDateHeader(req)
	AddAuthorizationHeader(vg, req, awsExampleProvider.secret)

	authErr := vg.AuthenticateRequest(req)
	assertNilError(t, authErr)
}

func TestGetFailsWithIncorrectSignature(t *testing.T) {
	vg := NewSingleProvider(awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)

	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)

	AddDateHeader(req)
	validSignature := vg.ConstructBase64Signature(req, awsExampleProvider.secret)
	invalidSignature := "aaaa" + validSignature
	req.Header.Set("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:"+invalidSignature)

	authErr := vg.AuthenticateRequest(req)
	assertError(t, authErr, ErrorHMACSignatureMismatch)
}

func TestAwsPut(t *testing.T) {
	vg := NewSingleProvider(awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)

	req, _ := http.NewRequest("PUT", "/johnsmith/photos/puppy.jpg", nil)
	AddDateHeader(req)
	req.Header.Set("Content-Type", "image/jpeg")
	req.Header.Set("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:MyyxeRY7whkBe+bq8fHCL/2kKUg=")
	AddAuthorizationHeader(vg, req, awsExampleProvider.secret)

	authErr := vg.AuthenticateRequest(req)
	assertNilError(t, authErr)
}

func TestAwsPutFail(t *testing.T) {
	vg := NewSingleProvider(awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)

	req, _ := http.NewRequest("PUT", "/johnsmith/photos/puppy.jpg", nil)
	AddDateHeader(req)
	req.Header.Set("Content-Type", "image/jpeg")
	// This signature is invalid.
	req.Header.Set("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:NyyxeRY7whkBe+bq8fHCL/2kKUg=")

	authErr := vg.AuthenticateRequest(req)
	assertError(t, authErr, ErrorHMACSignatureMismatch)
}

func TestAwsUpload(t *testing.T) {
	vg := NewSingleProvider(awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)
	vg.IncludeHeader("^X-Amz-.*")

	req, _ := http.NewRequest("PUT", "/static.johnsmith.net/db-backup.dat.gz", nil)
	AddDateHeader(req)
	req.Header.Set("Content-MD5", "4gJE4saaMU4BqNR0kLY+lw==")
	req.Header.Set("Content-Type", "application/x-download")

	// Custom Headers
	req.Header.Set("X-Amz-Acl", "public-read")
	req.Header.Set("X-Amz-Meta-ReviewedBy", "joe@johnsmith.net")
	req.Header.Add("X-Amz-Meta-ReviewedBy", "jane@johnsmith.net")
	req.Header.Set("X-Amz-Meta-FileChecksum", "0x02661779")
	req.Header.Set("X-Amz-Meta-ChecksumAlgorithm", "crc32")

	req.Header.Set("Content-Disposition", "attachment; filename=database.dat")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Content-Length", "5913339")

	AddAuthorizationHeader(vg, req, awsExampleProvider.secret)

	authErr := vg.AuthenticateRequest(req)
	assertNilError(t, authErr)
}

func TestAwsUploadFail(t *testing.T) {
	vg := NewSingleProvider(awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)

	req, _ := http.NewRequest("PUT", "/johnsmith/photos/puppy.jpg", nil)
	AddDateHeader(req)
	req.Header.Set("Content-Type", "image/jpeg")
	// This signature is invalid.
	req.Header.Set("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:NyyxeRY7whkBe+bq8fHCL/2kKUg=")

	authErr := vg.AuthenticateRequest(req)
	assertError(t, authErr, ErrorHMACSignatureMismatch)
}

func TestDateInBoundsSucceeds(t *testing.T) {
	vg := NewSingleProvider(awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)
	timeSkew := time.Minute * 30
	vg.SetMaxTimeSkew(timeSkew)

	// Mock clock.Now().
	present := time.Now()
	clock.Now = func() time.Time {
		return present
	}
	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)
	tooOld := present.Add(-1 * (timeSkew - time.Second))
	req.Header.Set("Date", tooOld.UTC().Format(time.RFC1123Z))
	AddAuthorizationHeader(vg, req, awsExampleProvider.secret)

	authErr := vg.AuthenticateRequest(req)
	assertNilError(t, authErr)
}

func TestDateMissingFails(t *testing.T) {
	vg := NewSingleProvider(awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)
	vg.SetMaxTimeSkew(time.Minute * 30)
	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)
	AddAuthorizationHeader(vg, req, awsExampleProvider.secret)

	authErr := vg.AuthenticateRequest(req)
	assertError(t, authErr, ErrorDateHeaderMissing)
}

func TestDateTooOldFails(t *testing.T) {
	vg := NewSingleProvider(awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)
	timeSkew := time.Minute * 30
	vg.SetMaxTimeSkew(timeSkew)

	// Mock clock.Now().
	present := time.Now()
	clock.Now = func() time.Time {
		return present
	}
	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)
	tooOld := present.Add(-1 * (time.Second + timeSkew))
	req.Header.Set("Date", tooOld.UTC().Format(time.RFC1123Z))
	AddAuthorizationHeader(vg, req, awsExampleProvider.secret)

	authErr := vg.AuthenticateRequest(req)
	assertError(t, authErr, ErrorDateHeaderTooSkewed)
}

func TestDateTooNewFails(t *testing.T) {
	vg := NewSingleProvider(awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)
	vg.SetMaxTimeSkew(time.Minute * 15)

	// Mock clock.Now().
	present := time.Now()
	clock.Now = func() time.Time {
		return present
	}
	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)
	skewedDateStr := (present.Add(time.Second)).UTC().Format(time.RFC1123Z)
	req.Header.Set("Date", skewedDateStr)
	AddAuthorizationHeader(vg, req, awsExampleProvider.secret)

	authErr := vg.AuthenticateRequest(req)
	assertError(t, authErr, ErrorDateHeaderTooFuture)
}

func TestDateMalformedFails(t *testing.T) {
	vg := NewSingleProvider(awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)
	date, err := time.Parse(time.RFC1123Z, "Tue, 27 Mar 2007 19:36:42 +0000")
	if err != nil {
		t.Error("Date couldn't be parsed")
	}
	skew := time.Now().Sub(date) + (time.Second * 10)
	vg.SetMaxTimeSkew(skew)

	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)
	req.Header.Set("Date", "2007-03-27T19:36:42Z00:00") // RFC 3339 - not supported
	req.Header.Set("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:bWq2s1WEIj+Ydj0vQ697zp+IXMU=")

	authErr := vg.AuthenticateRequest(req)
	assertError(t, authErr, ErrorDateHeaderMalformed)
}

func TestHandler(t *testing.T) {
	// Check that successfully authenticated requests reach the inner handler.
	testHandlerEntered := false
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testHandlerEntered = true
		w.WriteHeader(http.StatusOK)
	})
	vg := NewSingleProvider(awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)

	resp := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)
	AddDateHeader(req)
	AddAuthorizationHeader(vg, req, awsExampleProvider.secret)

	vg.Handler(testHandler).ServeHTTP(resp, req)
	if !(testHandlerEntered && resp.Code == http.StatusOK) {
		t.Error("Request should have succeeded.")
		t.FailNow()
	}

	// Check that badly authenticated requests never reach the inner handler.
	brokenHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should never be reached.")
		t.FailNow()
	})
	resp = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)
	AddDateHeader(req)
	validSignature := vg.ConstructBase64Signature(req, awsExampleProvider.secret)
	invalidSignature := "aaaa" + validSignature
	req.Header.Set("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:"+invalidSignature)

	vg.Handler(brokenHandler).ServeHTTP(resp, req)
	if resp.Code != http.StatusForbidden {
		t.Error("Success should have failed.")
		t.FailNow()
	}

	// Check that debug mode sets an error message in the response body.
	resp = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)
	AddDateHeader(req)
	validSignature = vg.ConstructBase64Signature(req, awsExampleProvider.secret)
	invalidSignature = "aaaa" + validSignature
	req.Header.Set("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:"+invalidSignature)

	vg.SetDebug(true)
	vg.Handler(brokenHandler).ServeHTTP(resp, req)

	if resp.Code != http.StatusForbidden {
		t.Error("Success should have failed.")
		t.FailNow()
	}
	if _, found := resp.Header()["Content-Type"]; !found {
		t.Error("Expected valid content-type header.")
		t.FailNow()
	}
	if len(resp.Body.Bytes()) == 0 {
		t.Error("Expected error description in body.")
		t.FailNow()
	}
}
