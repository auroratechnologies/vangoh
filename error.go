package vangoh

import (
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

// Utility function to write an HTTP status code to a request and return an error.
func errorAndSetHTTPStatus(w http.ResponseWriter, r *http.Request, status int, message string) error {
	w.WriteHeader(status)
	return &AuthenticationError{status, message}
}
