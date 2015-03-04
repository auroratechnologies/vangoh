package vangoh

/*
Set of tests for VanGoH checking against the examples provided on the AWS "Signing
and Authenticating REST Requests" page - http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html
*/

import (
	"crypto"
	_ "crypto/SHA1"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var awsExampleProvider = &testProvider{
	promptErr:  false,
	identifier: []byte("AKIAIOSFODNN7EXAMPLE"),
	secretKey:  []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
}

func awsGetVg() (*VanGoH, *httptest.ResponseRecorder, *http.Request) {
	vg := NewSingleProvider(awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)

	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)
	req.Header.Set("Date", "Tue, 27 Mar 2007 19:36:42 +0000")
	req.Header.Set("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:bWq2s1WEIj+Ydj0vQ697zp+IXMU=")
	w := httptest.NewRecorder()

	return vg, w, req
}

func TestAwsGet(t *testing.T) {
	vg, w, req := awsGetVg()

	vg.authenticateRequest(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Authentication didn't return expected status, instead returned %d,"+
			" with message %q", w.Code, w.Header().Get(errorMessageHeader))
	}
}

func TestAwsGetFail(t *testing.T) {
	vg := NewSingleProvider(awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)

	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)
	req.Header.Set("Date", "Tue, 27 Mar 2007 19:36:42 +0000")
	req.Header.Set("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:cWq2s1WEIj+Ydj0vQ697zp+IXMU=")
	w := httptest.NewRecorder()

	vg.authenticateRequest(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Authentication didn't return expected status, instead returned %d,"+
			" with message %q", w.Code, w.Header().Get(errorMessageHeader))
	}
}

func TestAwsPut(t *testing.T) {
	vg := NewSingleProvider(awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)

	req, _ := http.NewRequest("PUT", "/johnsmith/photos/puppy.jpg", nil)
	req.Header.Set("Date", "Tue, 27 Mar 2007 21:15:45 +0000")
	req.Header.Set("Content-Type", "image/jpeg")
	req.Header.Set("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:MyyxeRY7whkBe+bq8fHCL/2kKUg=")
	w := httptest.NewRecorder()

	vg.authenticateRequest(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Authentication didn't return expected status, instead returned %d,"+
			" with message %q", w.Code, w.Header().Get(errorMessageHeader))
	}
}

func TestAwsPutFail(t *testing.T) {
	vg := NewSingleProvider(awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)

	req, _ := http.NewRequest("PUT", "/johnsmith/photos/puppy.jpg", nil)
	req.Header.Set("Date", "Tue, 27 Mar 2007 21:15:45 +0000")
	req.Header.Set("Content-Type", "image/jpeg")
	req.Header.Set("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:NyyxeRY7whkBe+bq8fHCL/2kKUg=")
	w := httptest.NewRecorder()

	vg.authenticateRequest(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Authentication didn't return expected status, instead returned %d,"+
			" with message %q", w.Code, w.Header().Get(errorMessageHeader))
	}
}

func TestAwsUpload(t *testing.T) {
	vg := NewSingleProvider(awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)
	vg.IncludeHeader("^X-Amz-.*$")

	req, _ := http.NewRequest("PUT", "/static.johnsmith.net/db-backup.dat.gz", nil)
	req.Header.Set("Date", "Tue, 27 Mar 2007 21:06:08 +0000")
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

	req.Header.Set("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:ilyl83RwaSoYIEdixDQcA4OnAnc=")
	w := httptest.NewRecorder()

	vg.authenticateRequest(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Authentication didn't return expected status, instead returned %d,"+
			" with message %q", w.Code, w.Header().Get(errorMessageHeader))
	}
}

func TestAwsUploadFail(t *testing.T) {
	vg := NewSingleProvider(awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)

	req, _ := http.NewRequest("PUT", "/johnsmith/photos/puppy.jpg", nil)
	req.Header.Set("Date", "Tue, 27 Mar 2007 21:15:45 +0000")
	req.Header.Set("Content-Type", "image/jpeg")
	req.Header.Set("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:NyyxeRY7whkBe+bq8fHCL/2kKUg=")
	w := httptest.NewRecorder()

	vg.authenticateRequest(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Authentication didn't return expected status, instead returned %d,"+
			" with message %q", w.Code, w.Header().Get(errorMessageHeader))
	}
}

func TestTimeSkew(t *testing.T) {
	vg := NewSingleProvider(awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)
	date, err := time.Parse(time.RFC1123Z, "Tue, 27 Mar 2007 19:36:42 +0000")
	if err != nil {
		t.Error("Date couldn't be parsed")
	}
	skew := time.Now().Sub(date) + (time.Second * 10)
	vg.SetMaxTimeSkew(skew)

	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)
	req.Header.Set("Date", "Tue, 27 Mar 2007 19:36:42 +0000")
	req.Header.Set("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:bWq2s1WEIj+Ydj0vQ697zp+IXMU=")
	w := httptest.NewRecorder()

	vg.authenticateRequest(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Authentication didn't return expected status, instead returned %d,"+
			" with message %q", w.Code, w.Header().Get(errorMessageHeader))
	}
}

func TestTimeSkewFailue(t *testing.T) {
	vg := NewSingleProvider(awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)
	vg.SetMaxTimeSkew(time.Minute * 15)

	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)
	req.Header.Set("Date", "Tue, 27 Mar 2007 19:36:42 +0000")
	req.Header.Set("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:bWq2s1WEIj+Ydj0vQ697zp+IXMU=")
	w := httptest.NewRecorder()

	vg.authenticateRequest(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Authentication didn't return expected status, instead returned %d,"+
			" with message %q", w.Code, w.Header().Get(errorMessageHeader))
	}
}

func TestMalformedDate(t *testing.T) {
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
	w := httptest.NewRecorder()

	vg.authenticateRequest(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Authentication didn't return expected status, instead returned %d,"+
			" with message %q", w.Code, w.Header().Get(errorMessageHeader))
	}
}

// Use the AWS credentials to test handler functions
type testHandler struct {
	called bool
}

func newTestHandler() *testHandler {
	return &testHandler{
		called: false,
	}
}

func (th *testHandler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	th.called = true
}

func TestHandler(t *testing.T) {
	vg, w, req := awsGetVg()

	th := newTestHandler()

	handler := vg.Handler(th)

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Authentication didn't return expected status, instead returned %d,"+
			" with message %q", w.Code, w.Header().Get(errorMessageHeader))
	}

	if !th.called {
		t.Error("Handler wasn't called, despite valid authentication")
	}
}

func TestHandlerFailure(t *testing.T) {
	vg, w, req := awsGetVg()
	req.Header.Set("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:bWq2s1WEIj+Ydj0vQ697zq+IXMU=")

	th := newTestHandler()

	handler := vg.Handler(th)

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Authentication didn't return expected status, instead returned %d,"+
			" with message %q", w.Code, w.Header().Get(errorMessageHeader))
	}

	if th.called {
		t.Error("Handler was called, despite invalid authentication")
	}
}

func TestChainedHandler(t *testing.T) {
	vg, w, req := awsGetVg()

	th := newTestHandler()

	vg.ChainedHandler(w, req, th.ServeHTTP)

	if w.Code != http.StatusOK {
		t.Errorf("Authentication didn't return expected status, instead returned %d,"+
			" with message %q", w.Code, w.Header().Get(errorMessageHeader))
	}

	if !th.called {
		t.Error("Handler wasn't called, despite valid authentication")
	}
}

func TestMissingHeader(t *testing.T) {
	vg, w, req := awsGetVg()

	req.Header.Del("Authorization")

	vg.authenticateRequest(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Authentication didn't return expected status, instead returned %d,"+
			" with message %q", w.Code, w.Header().Get(errorMessageHeader))
	}
}

func TestMalformedHeader(t *testing.T) {
	vg, w, req := awsGetVg()

	req.Header.Set("Authorization", "MISSINGORGTAG:DOESNTMATTER=")

	vg.authenticateRequest(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Authentication didn't return expected status, instead returned %d,"+
			" with message %q", w.Code, w.Header().Get(errorMessageHeader))
	}
}

func TestMalformedB64(t *testing.T) {
	vg, w, req := awsGetVg()

	req.Header.Set("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:bWq2s1WEIj+/Ydj0vQ697zp+IXMU=")

	vg.authenticateRequest(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Authentication didn't return expected status, instead returned %d,"+
			" with message %q", w.Code, w.Header().Get(errorMessageHeader))
	}
}

func TestMultiProvider(t *testing.T) {
	vg := New()
	vg.AddProvider("AWS", awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)

	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)
	req.Header.Set("Date", "Tue, 27 Mar 2007 19:36:42 +0000")
	req.Header.Set("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:bWq2s1WEIj+Ydj0vQ697zp+IXMU=")
	w := httptest.NewRecorder()

	vg.authenticateRequest(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Authentication didn't return expected status, instead returned %d,"+
			" with message %q", w.Code, w.Header().Get(errorMessageHeader))
	}
}

func TestInvalidOrgTax(t *testing.T) {
	vg := New()
	vg.AddProvider("AWS", awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)

	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)
	req.Header.Set("Date", "Tue, 27 Mar 2007 19:36:42 +0000")
	req.Header.Set("Authorization", "AUR AKIAIOSFODNN7EXAMPLE:bWq2s1WEIj+Ydj0vQ697zp+IXMU=")
	w := httptest.NewRecorder()

	vg.authenticateRequest(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Authentication didn't return expected status, instead returned %d,"+
			" with message %q", w.Code, w.Header().Get(errorMessageHeader))
	}
}

var errTestProvider = &testProvider{
	promptErr:  true,
	identifier: []byte("AKIAIOSFODNN7EXAMPLE"),
	secretKey:  []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
}

func TestKeyLookupError(t *testing.T) {
	vg := New()
	vg.AddProvider("AWS", errTestProvider)
	vg.SetAlgorithm(crypto.SHA1.New)

	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)
	req.Header.Set("Date", "Tue, 27 Mar 2007 19:36:42 +0000")
	req.Header.Set("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:bWq2s1WEIj+Ydj0vQ697zp+IXMU=")
	w := httptest.NewRecorder()

	vg.authenticateRequest(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Authentication didn't return expected status, instead returned %d,"+
			" with message %q", w.Code, w.Header().Get(errorMessageHeader))
	}
}

func TestKeyNotFound(t *testing.T) {
	vg, w, req := awsGetVg()
	req.Header.Set("Authorization", "AWS NONEXISTENTKEY:bWq2s1WEIj+Ydj0vQ697zp+IXMU=")

	vg.authenticateRequest(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Authentication didn't return expected status, instead returned %d,"+
			" with message %q", w.Code, w.Header().Get(errorMessageHeader))
	}
}
