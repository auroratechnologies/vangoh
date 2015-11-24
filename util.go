package vangoh

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"time"
)

func AddDateHeader(r *http.Request) {
	AddCustomDateHeader(r, "Date")
}

func AddCustomDateHeader( r *http.Request, headerName string) {
	datestr := time.Now().UTC().Format(time.RFC1123Z)
	r.Header.Set(headerName, datestr)
}

func AddAuthorizationHeader(vg *Vangoh, r *http.Request, org string, key []byte, secret []byte) {
	signature := vg.ConstructBase64Signature(r, secret)
	r.Header.Set("Authorization", fmt.Sprintf("%s %s:%s", org, key, signature))
}

func (vg *Vangoh) ConstructBase64Signature(r *http.Request, secret []byte) string {
	return base64.StdEncoding.EncodeToString(vg.ConstructSignature(r, secret))
}
