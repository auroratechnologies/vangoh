package vangoh

import (
	"bytes"
	"crypto"
	_ "crypto/SHA1"
	"errors"
	"fmt"
	"hash"
	"net/http"
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

func assertErrorWithStatus(t *testing.T, a *AuthenticationError, status int) {
	if a == nil {
		t.Errorf("Expected an error with HTTP Status %d, but received no error", status)
		t.FailNow()
	}
	if a.StatusCode() != status {
		t.Errorf("Expected an error with status HTTP %d, but received HTTP %d", status, a.StatusCode())
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

type testCallbackProvider testProvider
type testCallbackData struct {
	Value string
}

func (tcp *testCallbackProvider) GetSecret(key []byte, voidPtr *unsafe.Pointer) ([]byte, error) {
	if tcp.promptErr {
		return nil, errors.New("testing error")
	}
	if !bytes.Equal(tcp.key, key) {
		return nil, nil
	}
	data := &testCallbackData{Value: "Hello!"}
	*voidPtr = unsafe.Pointer(data)
	return tcp.secret, nil
}

func (tcp *testCallbackProvider) SuccessCallback(r *http.Request, voidPtr *unsafe.Pointer) {
	dataPtr := (*testCallbackData)(*voidPtr)
	data := *dataPtr
	fmt.Printf("Value: %s\n", data.Value)
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

var awsExampleProvider = &testCallbackProvider{
	promptErr: false,
	key:       []byte("AKIAIOSFODNN7EXAMPLE"),
	secret:    []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
}

func TestNew(t *testing.T) {
	vg := New()

	if vg.includedHeaders == nil {
		t.Error("includeHeaders not properly intialized")
	}
	if vg.keyProviders == nil {
		t.Error("keyProviders not properly intialized")
	}
	if vg.singleProvider {
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
	if vg.keyProviders == nil {
		t.Error("keyProviders not properly intialized")
	}
	if !vg.singleProvider {
		t.Error("singleProvider constructor should create a single provider instance")
	}
}

func TestAddProvider(t *testing.T) {
	vg := New()

	if len(vg.keyProviders) != 0 {
		t.Error("Wrong number of key providers in the Vangoh instance")
	}

	err := vg.AddProvider("test", tp1)
	if err != nil {
		t.Error("Should not have encountered error when adding a new provider")
	}

	if len(vg.keyProviders) != 1 {
		t.Error("Wrong number of key providers in the Vangoh instance")
	}

	err = vg.AddProvider("test", tp2)
	if err == nil {
		t.Error("Should error when trying to add multiple providers for same org tag")
	}

	if len(vg.keyProviders) != 1 {
		t.Error("Wrong number of key providers in the Vangoh instance")
	}

	err = vg.AddProvider("notTest", tp2)
	if err != nil {
		t.Error("Should not error when trying to add multiple providers for different org tags")
	}

	if len(vg.keyProviders) != 2 {
		t.Error("Wrong number of key providers in the Vangoh instance")
	}

	spvg := NewSingleProvider(tp1)

	if len(spvg.keyProviders) != 1 {
		t.Error("Wrong number of key providers in the Vangoh instance")
	}

	err = spvg.AddProvider("test", tp2)
	if err == nil {
		t.Error("Should error when trying to add second provider to single provider instance")
	}

	if len(spvg.keyProviders) != 1 {
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
func TestAuthheaderMalformedFails(t *testing.T) {
	vg := NewSingleProvider(awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)

	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)

	AddDateHeader(req)
	// Add malformed header.
	req.Header.Set("Authorization", "wooo ORG KEY:SECRET")

	authErr := vg.AuthenticateRequest(req)
	assertError(t, authErr, ErrorAuthHeaderMalformed)
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
	assertErrorWithStatus(t, authErr, http.StatusForbidden)
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
	req.Header.Set("Date", "Tue, 27 Mar 2007 21:15:45 +0000")
	req.Header.Set("Content-Type", "image/jpeg")
	req.Header.Set("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:NyyxeRY7whkBe+bq8fHCL/2kKUg=")

	authErr := vg.AuthenticateRequest(req)
	assertErrorWithStatus(t, authErr, http.StatusForbidden)
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
	req.Header.Set("Date", "Tue, 27 Mar 2007 21:15:45 +0000")
	req.Header.Set("Content-Type", "image/jpeg")
	req.Header.Set("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:NyyxeRY7whkBe+bq8fHCL/2kKUg=")

	authErr := vg.AuthenticateRequest(req)
	assertErrorWithStatus(t, authErr, http.StatusForbidden)
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
	assertErrorWithStatus(t, authErr, http.StatusForbidden)
	if authErr.s != "Date header's value is too old" {
		t.Error("Expected rejection based on past time.")
		t.FailNow()
	}
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
	assertErrorWithStatus(t, authErr, http.StatusForbidden)
	if authErr.s != "Date header's value is in the future" {
		t.Error("Expected rejection based on future time.")
		t.FailNow()
	}
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
	assertErrorWithStatus(t, authErr, http.StatusBadRequest)
}
