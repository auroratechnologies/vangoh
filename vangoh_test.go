package vangoh

import (
	"bytes"
	"crypto"
	_ "crypto/sha1"
	"errors"
	"fmt"
	"hash"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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
	promptErr             bool
	key                   []byte
	secret                []byte
	modifyCallbackPayload bool
	T                     *testing.T
}

type testCallbackData struct{ Value string }

var testCallbackValue = "testcallbackvalue"

func (tcp *testCallbackProvider) GetSecret(key []byte, cbPayload *CallbackPayload) ([]byte, error) {
	if tcp.promptErr {
		return nil, errors.New("testing error")
	}
	if !bytes.Equal(tcp.key, key) {
		return nil, nil
	}
	if cbPayload.GetPayload() != nil {
		tcp.T.Error("Expected to be passed a nil cbPayload.")
		tcp.T.FailNow()
	}
	if tcp.modifyCallbackPayload {
		cbPayload.SetPayload(&testCallbackData{Value: testCallbackValue})
	}
	return tcp.secret, nil
}

func (tcp *testCallbackProvider) SuccessCallback(r *http.Request, cbPayload *CallbackPayload) {
	if tcp.modifyCallbackPayload && cbPayload.GetPayload() == nil {
		tcp.T.Error("Expected to be passed a valid cbPayload.")
		tcp.T.FailNow()
	}
	if !tcp.modifyCallbackPayload && cbPayload.GetPayload() != nil {
		tcp.T.Error("Expected to be passed a nil cbPayload.")
		tcp.T.FailNow()
	}
	payload := cbPayload.GetPayload()
	if payload != nil {
		data, ok := payload.(*testCallbackData)
		if !ok {
			tcp.T.Error("Expected callback payload to cast to testCallbackData")
			tcp.T.FailNow()
		}
		if data.Value != testCallbackValue {
			tcp.T.Error("Expected to unpack the test callback value.")
			tcp.T.FailNow()
		}
	}
}

var awsOrg = "AWS"
var awsKey = []byte("AKIAIOSFODNN7EXAMPLE")
var awsSecret = []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

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
	key:       awsKey,
	secret:    awsSecret,
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

func TestIncludeHeader(t *testing.T) {
	// Valid regex with ^ and $ should succeed unchanged.
	vg := New()
	valid := "^example$"
	vg.IncludeHeader(valid)
	if _, found := vg.includedHeaders[valid]; !found {
		t.Error("Valid regex was not left unmodified.")
	}

	// Valid regex without ^ should be fixed to include it.
	missingLeadingAnchor := "example$"
	vg = New()
	vg.IncludeHeader(missingLeadingAnchor)
	if _, found := vg.includedHeaders[missingLeadingAnchor]; found {
		t.Error("Regex without anchor prefix was not left unmodified.")
	}
	if _, found := vg.includedHeaders[valid]; !found {
		t.Error("Regex without anchor prefix was not fixed correctly.")
	}

	// Valid regex without $ should be fixed to include it.
	missingTrailingAnchor := "^example"
	vg = New()
	vg.IncludeHeader(missingTrailingAnchor)
	if _, found := vg.includedHeaders[missingTrailingAnchor]; found {
		t.Error("Regex without anchor suffix was not left unmodified.")
	}
	if _, found := vg.includedHeaders[valid]; !found {
		t.Error("Regex without anchor suffix was not fixed correctly.")
	}

	// Invalid regex should return an error after compilation fails.
	invalidRegex := "^($"
	vg = New()
	err := vg.IncludeHeader(invalidRegex)
	if err == nil {
		t.Error("Invalid regex should return an error when compilation fails.")
	}
	if len(vg.includedHeaders) != 0 {
		t.Error("Invalid regex should not result in any addition to includedHeaders.")
	}

	// Multiple matching regexes should not result in a header being added to the
	// signing string multiple times.
	vg = NewSingleProvider(awsExampleProvider)
	regexA := "^X-.*$" // Matches X-Test.
	err = vg.IncludeHeader(regexA)
	if err != nil {
		t.Error("Error adding valid header regex " + regexA)
		t.FailNow()
	}
	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)
	req.Header.Set("X-Test", "foo")
	AddDateHeader(req)
	AddAuthorizationHeader(vg, req, awsOrg, awsKey, awsSecret)

	authErr := vg.AuthenticateRequest(req)
	assertNilError(t, authErr)

	// Add a new header regex, so that there are two regexes that match the same
	// header, and try authenticating request with the exact same signature hash.
	// This should succeed because the signing bodies should be the same.
	regexB := "^X-T.*$" // Matches X-Test.
	err = vg.IncludeHeader(regexB)
	if err != nil {
		t.Error("Error adding valid header regex " + regexB)
		t.FailNow()
	}
	authErr = vg.AuthenticateRequest(req)
	assertNilError(t, authErr)
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
	AddAuthorizationHeader(vg, req, awsOrg, awsKey, awsSecret)

	authErr := vg.AuthenticateRequest(req)
	assertError(t, authErr, ErrorInProviderKeyLookup)
}

func TestCallbackProviderWithErrorFails(t *testing.T) {
	var tcpErr = &testCallbackProvider{
		promptErr:             true,
		key:                   awsKey,
		secret:                awsSecret,
		modifyCallbackPayload: true,
		T: t,
	}
	vg := NewSingleProvider(tcpErr)
	vg.SetAlgorithm(crypto.SHA1.New)

	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)

	AddDateHeader(req)
	AddAuthorizationHeader(vg, req, awsOrg, awsKey, awsSecret)

	authErr := vg.AuthenticateRequest(req)
	assertError(t, authErr, ErrorInProviderKeyLookup)
}

func TestCallbackProviderMissingSecret(t *testing.T) {
	var tcp = &testCallbackProvider{
		promptErr:             false,
		key:                   []byte("NOTTHERIGHTKEY"),
		secret:                []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
		modifyCallbackPayload: true,
		T: t,
	}
	vg := NewSingleProvider(tcp)
	vg.SetAlgorithm(crypto.SHA1.New)

	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)

	AddDateHeader(req)
	AddAuthorizationHeader(vg, req, awsOrg, awsKey, awsSecret)

	authErr := vg.AuthenticateRequest(req)
	assertError(t, authErr, ErrorSecretNotFound)
}

func TestCallbackProviderSucceedsWithoutModifyingPtr(t *testing.T) {
	var tcp = &testCallbackProvider{
		promptErr:             false,
		key:                   []byte(awsKey),
		secret:                []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
		modifyCallbackPayload: false,
		T: t,
	}
	vg := NewSingleProvider(tcp)
	vg.SetAlgorithm(crypto.SHA1.New)

	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)

	AddDateHeader(req)
	AddAuthorizationHeader(vg, req, awsOrg, awsKey, awsSecret)

	authErr := vg.AuthenticateRequest(req)
	assertNilError(t, authErr)
}

func TestCallbackProviderSucceeds(t *testing.T) {
	var tcp = &testCallbackProvider{
		promptErr:             false,
		key:                   []byte(awsKey),
		secret:                []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
		modifyCallbackPayload: true,
		T: t,
	}
	vg := NewSingleProvider(tcp)
	vg.SetAlgorithm(crypto.SHA1.New)

	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)

	AddDateHeader(req)
	AddAuthorizationHeader(vg, req, awsOrg, awsKey, awsSecret)

	authErr := vg.AuthenticateRequest(req)
	assertNilError(t, authErr)
}

func TestMissingProviderFails(t *testing.T) {
	vg := New()
	vg.SetAlgorithm(crypto.SHA1.New)

	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)

	AddDateHeader(req)
	AddAuthorizationHeader(vg, req, awsOrg, awsKey, awsSecret)

	authErr := vg.AuthenticateRequest(req)
	assertError(t, authErr, ErrorAuthOrgUnknown)
}
func TestNonSingleProviderSucceeds(t *testing.T) {
	vg := New()
	vg.AddProvider("AWS", awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)

	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)

	AddDateHeader(req)
	AddAuthorizationHeader(vg, req, awsOrg, awsKey, awsSecret)

	authErr := vg.AuthenticateRequest(req)
	assertNilError(t, authErr)
}

func TestGetSucceedsWithCorrectSignature(t *testing.T) {
	vg := NewSingleProvider(awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)

	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)

	AddDateHeader(req)
	AddAuthorizationHeader(vg, req, awsOrg, awsKey, awsSecret)

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
	AddAuthorizationHeader(vg, req, awsOrg, awsKey, awsSecret)

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

	AddAuthorizationHeader(vg, req, awsOrg, awsKey, awsSecret)

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
	AddAuthorizationHeader(vg, req, awsOrg, awsKey, awsSecret)

	authErr := vg.AuthenticateRequest(req)
	assertNilError(t, authErr)
}

func TestDateMissingFails(t *testing.T) {
	vg := NewSingleProvider(awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)
	vg.SetMaxTimeSkew(time.Minute * 30)
	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)
	AddAuthorizationHeader(vg, req, awsOrg, awsKey, awsSecret)

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
	AddAuthorizationHeader(vg, req, awsOrg, awsKey, awsSecret)

	authErr := vg.AuthenticateRequest(req)
	assertError(t, authErr, ErrorDateHeaderTooSkewed)
}

func TestDateTooNewFails(t *testing.T) {
	vg := NewSingleProvider(awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)
	maxTimeSkew := time.Minute * 15
	vg.SetMaxTimeSkew(maxTimeSkew)

	// Mock clock.Now().
	present := time.Now()
	clock.Now = func() time.Time {
		return present
	}
	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)
	skewedDateStr := (present.Add(maxTimeSkew + time.Second)).UTC().Format(time.RFC1123Z)
	req.Header.Set("Date", skewedDateStr)
	AddAuthorizationHeader(vg, req, awsOrg, awsKey, awsSecret)

	authErr := vg.AuthenticateRequest(req)
	assertError(t, authErr, ErrorDateHeaderTooSkewed)
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

func TestCustomDate(t *testing.T) {
	vg := NewSingleProvider(awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)
	vg.SetCustomDateHeader("X-AWS-Date")

	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)

	AddCustomDateHeader(req, "X-AWS-Date")
	AddAuthorizationHeader(vg, req, awsOrg, awsKey, awsSecret)

	authErr := vg.AuthenticateRequest(req)

	assertNilError(t, authErr)
}

func TestCustomDateFallback(t *testing.T) {
	vg := NewSingleProvider(awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)
	vg.SetCustomDateHeader("X-AWS-Date")

	vg2 := NewSingleProvider(awsExampleProvider)
	vg2.SetAlgorithm(crypto.SHA1.New)

	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)

	AddDateHeader(req)
	AddAuthorizationHeader(vg2, req, awsOrg, awsKey, awsSecret)

	authErr := vg.AuthenticateRequest(req)

	assertNilError(t, authErr)
}

func TestCustomDateMissingAllDates(t *testing.T) {
	vg := NewSingleProvider(awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)
	vg.SetCustomDateHeader("X-AWS-Date")

	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)

	AddAuthorizationHeader(vg, req, awsOrg, awsKey, awsSecret)

	authErr := vg.AuthenticateRequest(req)

	assertError(t, authErr, ErrorDateHeaderMissing)
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
	AddAuthorizationHeader(vg, req, awsOrg, awsKey, awsSecret)

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
