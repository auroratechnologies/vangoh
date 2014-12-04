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
)

var awsExampleProvider = &testProvider{
	promptErr:  false,
	identifier: []byte("AKIAIOSFODNN7EXAMPLE"),
	secretKey:  []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
}

func TestAwsGet(t *testing.T) {
	vg := NewSingleProvider(awsExampleProvider)
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
	vg.IncludeHeader("^x-amz-.*")

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
