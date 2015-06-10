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
