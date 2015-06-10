package vangoh

/*
Set of tests for Vangoh checking against the examples provided on the AWS "Signing
and Authenticating REST Requests" page - http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html
*/

import (
	"crypto"
	_ "crypto/SHA1"
	"net/http"
	"testing"
	"time"
)

var awsExampleProvider = &testCallbackProvider{
	promptErr: false,
	key:       []byte("AKIAIOSFODNN7EXAMPLE"),
	secret:    []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
}

func assertNilError(t *testing.T, a *AuthenticationError) {
	if a != nil {
		t.Errorf("Expected no error, instead received HTTP %d: %s", a.StatusCode(), a)
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

func TestGetFailsWithSkewedTime(t *testing.T) {
	vg := NewSingleProvider(awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)

	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)

	skewedDateStr := (time.Now().Add(-1 * vg.maxTimeSkew)).UTC().Format(time.RFC1123Z)
	req.Header.Set("Date", skewedDateStr)
	AddAuthorizationHeader(vg, req, awsExampleProvider.secret)

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

	authErr := vg.AuthenticateRequest(req)
	assertNilError(t, authErr)
}

func TestTimeSkewFailue(t *testing.T) {
	vg := NewSingleProvider(awsExampleProvider)
	vg.SetAlgorithm(crypto.SHA1.New)
	vg.SetMaxTimeSkew(time.Minute * 15)

	req, _ := http.NewRequest("GET", "/johnsmith/photos/puppy.jpg", nil)
	req.Header.Set("Date", "Tue, 27 Mar 2007 19:36:42 +0000")
	req.Header.Set("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:bWq2s1WEIj+Ydj0vQ697zp+IXMU=")

	authErr := vg.AuthenticateRequest(req)
	assertErrorWithStatus(t, authErr, http.StatusForbidden)
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

	authErr := vg.AuthenticateRequest(req)
	assertErrorWithStatus(t, authErr, http.StatusBadRequest)
}
