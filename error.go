package vangoh

import (
	"fmt"
	"net/http"
)

type AuthenticationError struct {
	c int
	s string
}

func (a *AuthenticationError) Error() string {
	return a.s
}

func (a *AuthenticationError) StatusCode() int {
	return a.c
}

func (a *AuthenticationError) WriteResponse(w http.ResponseWriter, debug bool) {
	w.WriteHeader(a.StatusCode())
	if debug {
		w.Header().Add("Content-Type", "text/plain")
		fmt.Fprintf(w, "%s", a)
	}
}

// Utility function to write an HTTP status code to a request and return an error.
func errorAndSetHTTPStatus(w http.ResponseWriter, r *http.Request, status int, message string) error {
	w.WriteHeader(status)
	return &AuthenticationError{status, message}
}

var ErrorAuthHeaderMissing = &AuthenticationError{
	c: http.StatusBadRequest,
	s: "Missing 'Authorization' header",
}

var ErrorAuthHeaderMalformed = &AuthenticationError{
	c: http.StatusBadRequest,
	s: "Authorization header does not match expected format",
}

var ErrorAuthHeaderInvalidEncoding = &AuthenticationError{
	c: http.StatusBadRequest,
	s: "Authorization signature is not in valid b64 encoding",
}

var ErrorDateHeaderMalformed = &AuthenticationError{
	c: http.StatusBadRequest,
	s: "Date header is not a valid format",
}

var ErrorDateHeaderTooFuture = &AuthenticationError{
	c: http.StatusForbidden,
	s: "Date header's value is in the future",
}

var ErrorDateHeaderTooSkewed = &AuthenticationError{
	c: http.StatusForbidden,
	s: "Date header's value is too old",
}

var ErrorAuthOrgUnknown = &AuthenticationError{
	c: http.StatusBadRequest,
	s: "Authentication organization is not recognized",
}

var ErrorInProviderKeyLookup = &AuthenticationError{
	c: http.StatusInternalServerError,
	s: "Unable to look up secret key",
}

var ErrorSecretNotFound = &AuthenticationError{
	c: http.StatusForbidden,
	s: "Authentication key is not recognized",
}

var ErrorHMACSignatureMismatch = &AuthenticationError{
	c: http.StatusForbidden,
	s: "HMAC signature does not match",
}
