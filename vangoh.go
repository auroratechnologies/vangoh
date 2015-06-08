package vangoh

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"fmt"
	"time"
	// Need to register the default hash function for constructors to work
	_ "crypto/sha256"
	"encoding/base64"
	"errors"
	"hash"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

/*
SecretKeyProvider is an interface that describes a source of retrieving secret keys,
given a unique identifier.  It defines one method, GetSecretKey, which, given an identifier
of type []byte, will return the corresponding secret key.

A naïve implementation may be to reference an in-memory map, but it is also trivial
to implement a KeyProvider via a database connection.

Errors returned are to be returned from GetSecretKey only in the event that an actual
error is encountered by the provider (I/O error, timeout, etc.).  In this case,
VanGoH will respond to the request with an HTTP code 500 - Internal Server Error.

If the identifier cannot be found by the key provider, expected behavior is to
return nil, nil.  This indicates to VanGoH that the identifier lookup failed, and
VanGoH will respond to the request with an HTTP code 403 error - Forbidden.
*/
type SecretKeyProvider interface {
	GetSecretKey(identifier []byte) ([]byte, error)
}

/*
Name of the header carrying Organization, Access ID, and HMAC Signature information.
*/
const HMACHeader = "Authorization"

/*
Expected regex format of the Authorization signature.

An authorization signature consists of three parts:

	Authorization: [ORG] [ACCESS_ID]:[HMAC_SIGNATURE]

The first component is an organizational tag, which must consist of at least one character,
and has a valid character set of alphanumeric characters and underscores.

This should be followed by a sinle space, and then the accessID, which also must
consist of one or more alphanumeric characters and/or underscores.

The access ID must be followed by a single colon ':' character, and then the signature,
encoded in Base64 (valid characters being all alphanumeric, plus "+", forward slash "/",
and equals sign "=" as padding on the end if needed.)

Any leading or trailing whitespace around the header will be trimmed before validation.
*/
const AuthRegex = "^[A-Za-z0-9_]+ [A-Za-z0-9_/+]+:" +
	"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"

/*
Newline character, definited in unicode, to avoid platform dependence.
*/
const newline = "\u000A"

/*
VanGoH is an object that forms the primary point of configuration of the middleware
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
		an application-wide prefix for headers to be used, i.e. X-Aur-Meta-User or
		X-Aur-Locale.  This could be represented with the include header "^X-Aur-"
	*/
	includedHeaders map[string]struct{}

	/*
		maxTimeSkew represents the required immediacy of a request for the server to
		determine its validity.  It's based off of the time specified in the date header,
		and compared to the server time when the request is recieved.  Defaults to 15 minutes
	*/
	maxTimeSkew time.Duration
	debug       bool
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
		maxTimeSkew:     time.Minute * 15,
		debug:           false,
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

Will error if the VanGoH instance was created for a single provider (using the
NewSingleProvider constructor), or if the org tag already has an identity provider
associated with it.

By supporting different providers based on org tags, there is the ability to configure
authentication sources based on user type or purpose.  For instance, if an endpoint is
going to be used by both a small set of internal services as well as external users,
you could create a different provider for each, as demonstrated below.

Example:
	func main() {
		// Provider for internal services credentials (not included with VanGoH)
		internalProvider := providers.NewInMemoryProvider(...)
		// Provider for normal user credentials (not included with VanGoH)
		userProvider := providers.NewDatabaseProvider(...)

		vg := vangoh.New()
		_ = vg.AddProvider("INT", internalProvider)
		_ = vg.AddProvider("API", userProvider)

		// Add VanGoH into your web stack
	}

In this example, any connections made with the authorization header "INT [userID]:[signature]"
will be authenticated using the internal provider, and connections with the header
"API [userID]:[signature]" will be authenticated against the user provider, which
may be much more scalable, but less performant than the internal provider.
*/
func (vg *VanGoH) AddProvider(org string, skp SecretKeyProvider) error {
	if vg.singleProvider {
		return errors.New("cannot add a provider when created for a single provider")
	}
	if _, ok := vg.keyProviders[org]; ok {
		return errors.New("cannot add more than one keyProvider for the same org tag")
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

func (vg *VanGoH) SetDebug(debug bool) {
	vg.debug = debug
}

/*
IncludeHeader adds a regex to the set of custom headers to be included when calculating
the HMAC hash for a given request.

It checks against the headers in their canonical form, with the first letter and every
letter following a hyphen uppercased, and the rest lowercased.

For instance, to match all headers beginning with "X-Aur-", we could include the header
regex "X-Aur-.*".  It is important to note that this funcationality uses traditional, non-POSIX
regular expressions, and will add anchoring to the provided regex if it is not included.

This means that the regex "X-Aur" will only match headers with key "X-Aur" exactly.  In
order to do prefix matching you must add a wildcard match after, i.e. "X-Aur.*"

If no custom headers are included, the signature will be derived from just the HTTP verb,
Content-Type, Content-MD5, and canonical path.

*/
func (vg *VanGoH) IncludeHeader(headerRegex string) error {
	var buf bytes.Buffer
	if !strings.HasPrefix(headerRegex, "^") {
		buf.WriteString("^")
	}
	buf.WriteString(headerRegex)
	if !strings.HasSuffix(headerRegex, "$") {
		buf.WriteString("$")
	}

	regex := buf.String()

	_, err := regexp.Compile(regex)
	if err != nil {
		return err
	}

	vg.includedHeaders[regex] = struct{}{}

	return nil
}

/*
SetMaxTimeSkew sets the maximum allowable duration between the date and time specified
in the Date header and the server time when the response is processed.  If the date in
the header exceeds the duration VanGoH will respond to the request with a 403 forbidden
error.

For example, to match the behavior of AWS, which has a 15 minute allowable time skew
window, you could configure your VanGoH instance like this:

	vg := vangoh.New()
	vg.SetMaxTimeSkew(time.Minute * 15)

When checking the date header, VanGoH follows the precedent of RFC 2616, accepting dates
in any of the following formats:
	ANSIC       = "Mon Jan _2 15:04:05 2006"
	RFC822      = "02 Jan 06 15:04 MST"
	RFC822Z     = "02 Jan 06 15:04 -0700"
	RFC850      = "Monday, 02-Jan-06 15:04:05 MST"
	RFC1123     = "Mon, 02 Jan 2006 15:04:05 MST"
	RFC1123Z    = "Mon, 02 Jan 2006 15:04:05 -0700"
*/
func (vg *VanGoH) SetMaxTimeSkew(timeSkew time.Duration) {
	vg.maxTimeSkew = timeSkew
}

/*
Handler returns an implementation of the http.HandlerFunc type for integration
with the net/http library.

Example integration:
	func main() {
		// Creating our new VanGoH instance
		vg := vangoh.New()

		// Additional configuration and creation of the base handler

		// Route the handler through VanGoH, and ListenAndServer as usual
		app := vg.Handler(baseHandler)
		http.ListenAndServe("0.0.0.0:3000", app)
	}
*/
func (vg *VanGoH) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hand the request off to be authenticated.  If an error is encountered, err will be
		// non-null, but authenticateRequest will take care of writing the appropriate http
		// response on the ResponseWriter
		err := vg.authenticateRequest(w, r)
		if err != nil {
			if vg.debug {
				w.Header().Add("Content-Type", "text/plain")
				fmt.Fprintf(w, "%s", err)
			}
			return
		}
		h.ServeHTTP(w, r)
	})
}

/*
ChainedHandler is an implementation designed to integrate with Negroni, but may be
used in anything requiring the chainable signature.

Example use with Negroni:
	func main() {

		mux := http.NewServeMux()

		// Creating our new VanGoH instance
		vg := vangoh.NewSingleProvider(keyProvider)

		n := negroni.New(negroni.NewRecovery(), negroni.NewLogger(), negroni.HandlerFunc(vg.ChainedHandler))
		n.UseHandler(mux)

		n.Run(":3000")
	}
*/
func (vg *VanGoH) ChainedHandler(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	/*
		Hand the request off to be authenticated.  If an error is encountered, err will be
		non-null, but authenticateRequest will take care of writing the appropriate http
		response on the ResponseWriter.
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
a non-nil error, and writes an appropriate HTTP response on the provided ResponseWriter.
*/
func (vg *VanGoH) authenticateRequest(w http.ResponseWriter, r *http.Request) error {
	// Verify authorization header exists and is not malformed, and separate components.
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader == "" {
		return errorAndSetHTTPStatus(w, r, http.StatusBadRequest, "Missing 'Authorization' header")
	}

	match, err := regexp.Match(AuthRegex, []byte(authHeader))
	if err != nil || !match {
		return errorAndSetHTTPStatus(w, r, http.StatusBadRequest, "Authorization header does not match expected format")
	}

	orgSplit := strings.Split(authHeader, " ")
	org := orgSplit[0]

	idSplit := strings.Split(orgSplit[1], ":")
	accessID := idSplit[0]
	actualSignatureB64 := idSplit[1]
	actualSignature, err := base64.StdEncoding.DecodeString(actualSignatureB64)
	if err != nil {
		return errorAndSetHTTPStatus(w, r, http.StatusBadRequest, "Authorization signature is not in valid b64 encoding")
	}

	// Always check for excessive time skew in request.
	dateHeader := strings.TrimSpace(r.Header.Get("Date"))
	date, err := multiFormatDateParse([]string{time.RFC822, time.RFC822Z, time.RFC850,
		time.ANSIC, time.RFC1123, time.RFC1123Z}, dateHeader)
	if err != nil {
		return errorAndSetHTTPStatus(w, r, http.StatusBadRequest, "Date header is not a valid format")
	}
	diff := time.Now().Sub(date)
	if diff > vg.maxTimeSkew {
		return errorAndSetHTTPStatus(w, r, http.StatusForbidden, "Date header's value is too old")
	}

	// Load the secret key from the appropriate key provider, given the ID from the
	// Authorization header.

	// TODO: Both loading the secret key and generating the signature are independent
	// operations and potentially heavy, being possiby i/o bound and computationally
	// heavy respectively.  It may make sense to split them into go routines and execute
	// concurrently.
	providerKey := "*"
	if !vg.singleProvider {
		providerKey = org
	}

	provider, exists := vg.keyProviders[providerKey]
	if !exists {
		return errorAndSetHTTPStatus(w, r, http.StatusBadRequest, "Authorization organization is not recognized")
	}

	secretKey, err := provider.GetSecretKey([]byte(accessID))
	if err != nil {
		return errorAndSetHTTPStatus(w, r, http.StatusInternalServerError, "Unable to look up secret key")
	}
	if secretKey == nil {
		return errorAndSetHTTPStatus(w, r, http.StatusForbidden, "Authorization key is not recognized")
	}

	// Calculate the string to be signed based on the headers and VanGoH configuration.
	signingString, err := vg.createSigningString(w, r)
	if err != nil {
		return errorAndSetHTTPStatus(w, r, http.StatusInternalServerError, "Unable to create signature")
	}

	// Conduct our own signing and verify against the signature in the Authorization header.
	mac := hmac.New(vg.algorithm, secretKey)
	mac.Write([]byte(signingString))
	expectedSignature := mac.Sum(nil)

	if !hmac.Equal(expectedSignature, actualSignature) {
		return errorAndSetHTTPStatus(w, r, http.StatusForbidden, "HMAC signature does not match")
	}

	// If we have made it this far, authorization is successful.
	return nil
}

func multiFormatDateParse(formats []string, dateStr string) (time.Time, error) {
	for index := range formats {
		if date, err := time.Parse(formats[index], dateStr); err == nil {
			return date, nil
		}
	}
	return time.Time{}, errors.New("Date does not match any valid format")
}

/*
createSigningString creates the string used for signature generation, in accordance with
the specifications as laid out in the package documentation. Refer there for more detail,
or to the Amazon Signature V2 documentation: http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html.
*/
func (vg *VanGoH) createSigningString(w http.ResponseWriter, r *http.Request) (string, error) {
	var buffer bytes.Buffer

	buffer.WriteString(r.Method)
	buffer.WriteString(newline)

	buffer.WriteString(r.Header.Get("Content-MD5"))
	buffer.WriteString(newline)

	buffer.WriteString(r.Header.Get("Content-Type"))
	buffer.WriteString(newline)

	buffer.WriteString(r.Header.Get("Date"))
	buffer.WriteString(newline)

	customHeaders, err := vg.createHeadersString(r)
	if err != nil {
		return "", errors.New("Unable to create headers string")
	}
	buffer.WriteString(customHeaders)

	buffer.WriteString(r.URL.Path)

	return buffer.String(), nil
}

/*
createHeadersString is used to create the canonicalized header string, using the
custom headers as configured in the VanGoH object.

More detail on the methodology used in formatting the headers sting can be found
in the package documentation.
*/
func (vg *VanGoH) createHeadersString(r *http.Request) (string, error) {
	// return fast if no header regexes are defined
	if len(vg.includedHeaders) == 0 {
		return "", nil
	}

	// Buffer to write the canonicalized header string into as it's created
	var buffer bytes.Buffer

	/*
		For each defined regex, determine the set of headers that match.  Repeat for
		all regexes, without duplication, to get the final set of custom headers to use.
	*/
	var sanitizedHeaders = make(map[string][]string)

	for regex := range vg.includedHeaders {
		// Error was checked at creation
		compiledRegex, _ := regexp.Compile(regex)
		for header := range r.Header {
			lowerHeader := strings.ToLower(header)
			if _, found := sanitizedHeaders[lowerHeader]; found {
				continue
			}
			if compiledRegex.MatchString(header) {
				sanitizedHeaders[lowerHeader] = r.Header[header]
			}
		}
	}

	var orderedHeaders []string
	for header := range sanitizedHeaders {
		orderedHeaders = append(orderedHeaders, header)
	}
	sort.Strings(orderedHeaders)

	/*
		At this point sanitized contains all the headers to be included in the
		hash.  Now we need to retrieve their values, and sanitize them appropriately
	*/

	for header := range orderedHeaders {
		buffer.WriteString(orderedHeaders[header])
		buffer.WriteString(":")

		var sanitizedValues []string
		for i := range sanitizedHeaders[orderedHeaders[header]] {
			str := sanitizedHeaders[orderedHeaders[header]][i]
			str = strings.TrimSpace(str)
			str = strings.Replace(str, "\n", "", -1)
			sanitizedValues = append(sanitizedValues, str)
		}

		/*
			Note that sanitizedValues are unsorted here - the order that they are specified
			in the header will affect the hash result.

			This conforms with the standard set by AWS, tho it may be more reliable to add
			this sorting in at some point.
		*/

		for i := range sanitizedValues {
			buffer.WriteString(sanitizedValues[i])
			if i < (len(sanitizedValues) - 1) {
				buffer.WriteString(",")
			}
		}

		buffer.WriteString(newline)
	}

	return buffer.String(), nil
}
