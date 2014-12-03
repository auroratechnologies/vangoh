package vangoh

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	// Need to register the default hash function for constructors to work
	_ "crypto/sha256"
	"encoding/base64"
	"errors"
	"hash"
	"net/http"
	"regexp"
	"strings"
)

/*
SecretKeyProvider is an interface that describes a source of retrieving secret keys,
given a unique identifier.  It defines one method, GetSecretKey, which, given an identifier
of type byte[], will return the corresponding secret key.

A naïve implementation may be to reference an in-memory map, but it is also trivial
to implement a KeyProvider via a database connection.

In the event that an error is encountered in retrieving the key, an error should
be propogated up to be handled by the server.  The server will then respond with
a HTTP code 500 internal server error, and report the error string with its response.
*/
type SecretKeyProvider interface {
	GetSecretKey(identifier []byte) ([]byte, error)
}

/*
Header that the HMAC signature information is expected to be placed in
*/
const HMACHeader = "Authorization"

/*
Expected regex format of the Authorization signature, as described in the package
documentation.
*/
const AuthRegex = "^[A-Za-z0-9_]+ [A-Za-z0-9_]+:" +
	"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"

/*
VanGoH is a struct that forms the primary point of configuration of the middleware
HMAC handler.  It allows for the configuration of the hashing function to use, the
headers (specified as regexes) to be included in the computed signature, and the
mapping between organization tags and the secret key providers associated with them.
*/
type VanGoH struct {
	/*
		singleProvider indicates if there is one global provider for this HMAC checker.
		If so it can more efficiently skip checking which provider is appropriate for
		which org, all requests will auth against the same provider regardless of org tag.
	*/
	singleProvider bool

	/*
		keyProviders is a map between org tags, as used in the Authentication section,
		with the SecretKeyProvider that provides the identities for that org.
	*/
	keyProviders map[string]SecretKeyProvider

	/*
		algorithm represents the hashing function to be used when computing the HMAC hashes.
		Common algorithms for HMAC include SHA1, SHA256, and MD5, but any object that
		implements hash.Hash should work.
	*/
	algorithm func() hash.Hash

	/*
		includedHeaders specifies, as a slice of regex strings, which headers should
		be used in computing the HMAC signature for each request.  It is common to have
		an application-wide prefix for headers to be used, i.e. x-aur-meta-user or
		x-aur-locale.  This could be represented with the include header "^x-aur-"
	*/
	includedHeaders map[string]struct{}
}

/*
New creates a new VanGoH instance, defaulting to SHA256 hashing and with no included
headers or keyProviders.

They can be added with VanGoH.AddProvider(org string, skp SecretKeyProvider) and
VanGoH.IncludeHeader(headerRegex string) respectively
*/
func New() *VanGoH {
	return &VanGoH{
		singleProvider:  false,
		keyProviders:    make(map[string]SecretKeyProvider),
		algorithm:       crypto.SHA256.New,
		includedHeaders: make(map[string]struct{}),
	}
}

/*
NewSingleProvider creates a new VanGoH instance that supports a single
SecretKeyProvider, defaulting to SHA256 hashing and with no included headers.

Headers can be added with VanGoH.IncludeHeader(headerRegex string)

A VanGoH instance created for a single provider will error if an attempt to add
additional providers is made.
*/
func NewSingleProvider(provider SecretKeyProvider) *VanGoH {
	vg := New()
	vg.singleProvider = true
	vg.keyProviders["*"] = provider
	return vg
}

/*
AddProvider adds a new SecretKeyProvider, which the org tag maps to.

Will error if the VanGoH instance was created for a single provider, or if
the org tag already has an identity provider associated with it.
*/
func (vg *VanGoH) AddProvider(org string, skp SecretKeyProvider) error {
	if vg.singleProvider {
		return errors.New("Cannot add a provider when created for a single provider")
	}
	if _, ok := vg.keyProviders[org]; ok {
		return errors.New("Cannot add more than one keyProvider for the same org tag")
	}
	vg.keyProviders[org] = skp
	return nil
}

/*
SetAlgorithm sets the hashing algorithm to use for this VanGoH instance.

It takes as a parameter a function that returns type hash.Hash.  This is usually
the "New" method for a given hashing implementation (ie. crypto.SHA1.New)

In order to set the algorithm, you need to add an import to the algorithm directly,
even tho most are part of the crypto package:

  import _ "crypto/SHA1"

	...

	vg := vangoh.New()
	vg.SetAlgorithm(crypto.SHA1.New)

This is because in the hash init blocks, the hashes are registered with the crypto
package, and the init blocks are only run when the hash implementations are directly
imported.
*/
func (vg *VanGoH) SetAlgorithm(algorithm func() hash.Hash) {
	vg.algorithm = algorithm
}

/*
Handler returns an implementation of the http.HandlerFunc type for integration
with the net/http library
*/
func (vg *VanGoH) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		/*
			Hand the request off to be authenticated.  If an error is encountered, err will be
			non-null, but authenticateRequest will take care of writing the appropriate http
			response on the ResponseWriter
		*/
		err := vg.authenticateRequest(w, r)

		if err != nil {
			return
		}

		h.ServeHTTP(w, r)
	})
}

/*
ChainedHandler is an implementation designed to integrate with Negroni, but may be
used in anything requiring the chainable signature
*/
func (vg *VanGoH) ChainedHandler(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	/*
		Hand the request off to be authenticated.  If an error is encountered, err will be
		non-null, but authenticateRequest will take care of writing the appropriate http
		response on the ResponseWriter
	*/
	err := vg.authenticateRequest(w, r)

	if err == nil && next != nil {
		next(w, r)
	}
}

/*
authenticateRequest is the method where the validation work takes place.

Given a request, it first validates that there is an Authorization header present,
and that it fits the required format.  It then makes a call to load the secret key
from the appropriate key provider, and proceeds to construct the string used in signing.

If multiple Authorization headers exist, it uses the first only.

The signing string uses the configurations in the VanGoH instance to choose and format
the canonical headers, canonical path, date, content type, content md5, and http-verb.

Once the signing string formatting is completed and the secret key is retrieved from
the provider, the server re-calculates the hash of the request using the secret key
and compares it to the reported signature from the Authorization header.

If the keys match, the method returns without error.  Otherwise, the method returns
a non-nill error, and writes an appropriate HTTP response on the provided ResponseWriter.
*/
func (vg *VanGoH) authenticateRequest(w http.ResponseWriter, r *http.Request) error {
	/*
		Verify authorization header exists and is not malformed, and separate components
	*/
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		missingHeader.respond(w, r, *vg)
		return errors.New("Missing Header")
	}

	match, err := regexp.Match(AuthRegex, []byte(authHeader))
	if err != nil || !match {
		malformedHeader.setError(err).respond(w, r, *vg)
		return errors.New("Malformed Header")
	}

	orgSplit := strings.Split(authHeader, " ")
	org := orgSplit[0]

	idSplit := strings.Split(orgSplit[1], ":")
	accessID := idSplit[0]
	actualSignatureB64 := idSplit[1]
	actualSignature, err := base64.StdEncoding.DecodeString(actualSignatureB64)
	if err != nil {
		malformedHeader.setError(err).respond(w, r, *vg)
		return errors.New("Malformed Header")
	}

	/*
		Load the secret key from the appropriate key provider, given the ID from the
		Authorization header
	*/
	providerKey := "*"
	if !vg.singleProvider {
		providerKey = org
	}

	provider, exists := vg.keyProviders[providerKey]
	if !exists {
		invalidOrgTag.respond(w, r, *vg)
		return errors.New("Invalid Org Tag")
	}

	secretKey, err := provider.GetSecretKey([]byte(accessID))
	if err != nil {
		keyLookupFailure.setError(err).respond(w, r, *vg)
		return errors.New("keyLookupFailure")
	}
	if secretKey == nil {
		unableToAuthenticate.respond(w, r, *vg)
		return errors.New("ID not found")
	}

	/*
	  Calculate the string to be signed based on the headers and VanGoH configuration
	*/
	signingString, err := vg.createSigningString(w, r)
	if err != nil {
		signingFailure.setError(err).respond(w, r, *vg)
		return errors.New("Signing Failure")
	}

	/*
		Conduct our own signing and verify against the signature in the Authorization header
	*/
	mac := hmac.New(vg.algorithm, secretKey)
	mac.Write([]byte(signingString))
	expectedSignature := mac.Sum(nil)

	if !hmac.Equal(expectedSignature, actualSignature) {
		unableToAuthenticate.respond(w, r, *vg)
		return errors.New("Mismatched signatures")
	}

	/*
		If we have made it this far, authorization is successful.  Return nil error
	*/
	return nil
}

/*
createSigningString creates the string used for signature generation, in accordance with
the specifications as laid out in the package documentation.  Refer there for more detail.
*/
func (vg *VanGoH) createSigningString(w http.ResponseWriter, r *http.Request) (string, error) {
	var buffer bytes.Buffer
	newline := "\u000A"

	buffer.WriteString(r.Method)
	buffer.WriteString(newline)

	buffer.WriteString(r.Header.Get("Content-MD5"))
	buffer.WriteString(newline)

	buffer.WriteString(r.Header.Get("Content-Type"))
	buffer.WriteString(newline)

	buffer.WriteString(r.Header.Get("Date"))
	buffer.WriteString(newline)

	buffer.WriteString("")
	buffer.WriteString(r.URL.Path)

	return buffer.String(), nil
}
