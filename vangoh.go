package vangoh

import (
	"crypto"
	// Need to register the default hash function for constructors to work
	_ "crypto/SHA256"
	"errors"
	"hash"
)

/*
SecretKeyProvider is an interface that describes a source of of getting secret keys,
given a unique identifier.  It defines one method, GetSecretKey, which, given an identifier
of type byte[], will return the corresponding secret key.

A naïve implementation may be to reference an in-memory map, but it is also trivial
to implement a KeyProvider via a database connection.

In the event that an error is encountered in retrieving the key, an error should
be propogated up to be handled by the server.  The server will then respond with
a HTTP code 500 internal server error, and report the error string with its response.

In this manner you can provide more information of what the error is - a missing
identifier, an i/o error, etc.
*/
type SecretKeyProvider interface {
	GetSecretKey(identifier []byte) ([]byte, error)
}

/*
VanGoH is a struct that forms the primary point of configuration of the middleware
HMAC handler.  It allows for the configuration of the hashing function to use, the
headers, specified as regexes, to be included in the computed signature, and the
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
	algorithm hash.Hash

	algoFunc func() hash.Hash

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
		algorithm:       crypto.SHA256.New(),
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
	return nil
}

/*
SetAlgorithm sets the hashing algorithm to use for this VanGoH instance
*/
func (vg *VanGoH) SetAlgorithm(algorithm hash.Hash) {
	vg.algorithm = algorithm
}
