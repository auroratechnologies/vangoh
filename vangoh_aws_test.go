package vangoh

/*
Set of tests for VanGoH checking against the examples provided on the AWS "Signing
and Authenticating REST Requests" page - http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html
*/

import (
	"crypto"
	_ "crypto/SHA1"
	"crypto/hmac"
	_ "crypto/sha256"
	"encoding/base64"
	//"fmt"
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

func constructTestHMACb64(t *testing.T, vg *VanGoH, r *http.Request, secret []byte) string {
	signingString, err := vg.CreateSigningString(r)
	if err != nil {
		t.Errorf("constructTestHeader: unable to create signature.")
		t.FailNow()
	}
	mac := hmac.New(vg.algorithm, secret)
	mac.Write([]byte(signingString))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return signature
}

func addDateHeader(r *http.Request) {
	datestr := time.Now().UTC().Format(time.RFC1123Z)
	r.Header.Set("Date", datestr)
}

func addAuthorizationHeader(t *testing.T, vg *VanGoH, r *http.Request, secret []byte) {
	signature := constructTestHMACb64(t, vg, r, secret)
	r.Header.Set("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:"+signature)
}

func assertStatus(t *testing.T, status int, w *httptest.ResponseRecorder) {
	if w.Code != status {
		t.Errorf(
			"Authentication didn't return expected status, instead returned %d",
			w.Code)
		t.FailNow()
	}
}

func TestGetSucceedsWithCorrectSignature(t *testing.T) {
	vg := NewSingleProvider(awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)

	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)
	w := httptest.NewRecorder()

	addDateHeader(req)
	addAuthorizationHeader(t, vg, req, awsExampleProvider.secretKey)

	vg.authenticateRequest(w, req)
	assertStatus(t, http.StatusOK, w)
}

func TestGetFailsWithIncorrectSignature(t *testing.T) {
	vg := NewSingleProvider(awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)

	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)
	w := httptest.NewRecorder()

	addDateHeader(req)
	validSignature := constructTestHMACb64(t, vg, req, awsExampleProvider.secretKey)
	invalidSignature := "aaaa" + validSignature
	req.Header.Set("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:"+invalidSignature)

	vg.authenticateRequest(w, req)
	assertStatus(t, http.StatusForbidden, w)
}

func TestGetFailsWithSkewedTime(t *testing.T) {
	vg := NewSingleProvider(awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)

	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)
	w := httptest.NewRecorder()

	skewedDateStr := (time.Now().Add(-1 * vg.maxTimeSkew)).UTC().Format(time.RFC1123Z)
	req.Header.Set("Date", skewedDateStr)
	addAuthorizationHeader(t, vg, req, awsExampleProvider.secretKey)

	vg.authenticateRequest(w, req)
	assertStatus(t, http.StatusForbidden, w)
}

func TestAwsPut(t *testing.T) {
	vg := NewSingleProvider(awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)

	req, _ := http.NewRequest("PUT", "/johnsmith/photos/puppy.jpg", nil)
	addDateHeader(req)
	req.Header.Set("Content-Type", "image/jpeg")
	req.Header.Set("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:MyyxeRY7whkBe+bq8fHCL/2kKUg=")
	w := httptest.NewRecorder()
	addAuthorizationHeader(t, vg, req, awsExampleProvider.secretKey)

	vg.authenticateRequest(w, req)
	assertStatus(t, http.StatusOK, w)
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
	assertStatus(t, http.StatusForbidden, w)
}

func TestAwsUpload(t *testing.T) {
	vg := NewSingleProvider(awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)
	vg.IncludeHeader("^X-Amz-.*")

	req, _ := http.NewRequest("PUT", "/static.johnsmith.net/db-backup.dat.gz", nil)
	addDateHeader(req)
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

	w := httptest.NewRecorder()
	addAuthorizationHeader(t, vg, req, awsExampleProvider.secretKey)

	vg.authenticateRequest(w, req)
	assertStatus(t, http.StatusOK, w)
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
	assertStatus(t, http.StatusForbidden, w)
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
	assertStatus(t, http.StatusOK, w)
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
	assertStatus(t, http.StatusForbidden, w)
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
	assertStatus(t, http.StatusBadRequest, w)
}
