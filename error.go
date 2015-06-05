package vangoh

import (
	"errors"
	"net/http"
)

// Utility function to write an HTTP status code to a request and return an error.
func errorAndSetHTTPStatus(
	w http.ResponseWriter, req *http.Request, statusCode int, message string) error {
	w.WriteHeader(statusCode)
	return errors.New(message)
}
