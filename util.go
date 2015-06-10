package vangoh

import (
	"encoding/base64"
	"net/http"
	"time"
)

func AddDateHeader(r *http.Request) {
	datestr := time.Now().UTC().Format(time.RFC1123Z)
	r.Header.Set("Date", datestr)
}

// TODO(peter): org and key arguments
func AddAuthorizationHeader(vg *Vangoh, r *http.Request, secret []byte) {
	signature := vg.ConstructBase64Signature(r, secret)
	r.Header.Set("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:"+signature)
}

func (vg *Vangoh) ConstructBase64Signature(r *http.Request, secret []byte) string {
	return base64.StdEncoding.EncodeToString(vg.ConstructSignature(r, secret))
}
