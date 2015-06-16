package vangoh

import (
	"net/http"
)

/*
Protect a `http.Handler` from unauthenticated requests. The wrapped handler
will only be called if the request contains a valid Authorization header.

Example:
	func main() {
		// Create a new Vangoh instance.
		vg := vangoh.New()

		// Assuming the endpoint to be protected is called 'baseHandler'.
		protectedHandler := vg.Handler(unprotectedHandler)

		// Works just like any other `http.Handler`.
		http.ListenAndServe("0.0.0.0:3000", protectedHandler)
	}
*/
func (vg *Vangoh) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hand the request off to be authenticated.  If an error is encountered,
		// err will be non-null, but AuthenticateRequest will take care of writing
		// the appropriate http response on the ResponseWriter
		authErr := vg.AuthenticateRequest(r)
		if authErr != nil {
			authErr.WriteResponse(w, vg.GetDebug())
			return
		}
		h.ServeHTTP(w, r)
	})
}

/*
Implements the `negroni.Handler` interface, for use as a middleware.

Example:
	func main() {
		mux := http.NewServeMux()

		// Create a new Vangoh instance.
		vg := vangoh.New()

		// Create a new Negroni instance, with the standard Recovery and Logger
		// middlewares.
		n := negroni.New(
			negroni.NewRecovery(),
			negroni.NewLogger(),
			negroni.HandlerFunc(vg.NegroniHandler))

		// Run the app.
		n.UseHandler(mux)
		n.Run(":3000")
	}
*/
func (vg *Vangoh) NegroniHandler(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	// Hand the request off to be authenticated.  If an error is encountered, err
	// will be non-null, but AuthenticateRequest will take care of writing the
	// appropriate http response on the ResponseWriter
	authErr := vg.AuthenticateRequest(r)
	if authErr != nil {
		authErr.WriteResponse(w, vg.GetDebug())
		return
	}
	next(w, r)
}
