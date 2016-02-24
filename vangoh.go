package vangoh

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	_ "crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"hash"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
	"unsafe"
)

// Expected regex format of the Authorization signature.
//
// An authorization signature consists of three parts:
//
// 	Authorization: [ORG] [KEY]:[HMAC_SIGNATURE]
//
// The first component is an organizational tag, which must consist of at least
// one character, and has a valid character set of alphanumeric characters and
// underscores.
//
// This should be followed by a single space, and then the key, which also must
// consist of one or more alphanumeric characters and/or underscores.
//
// The key must be followed by a single colon ':' character, and then the
// signature, encoded in Base64 (valid characters being all alphanumeric, plus
// "+", forward slash "/", and equals sign "=" as padding on the end if
// needed.)
//
// Any leading or trailing whitespace around the header will be trimmed before
// validation.
const AuthRegex = "^[A-Za-z0-9_]+ [A-Za-z0-9_/+]+:" +
	"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"

// Newline character, defined in unicode to avoid platform dependence.
const newline = "\u000A"

// The names of the supported formats for the timestamp in the Date HTTP
// header. If the timestamp does not match one of these formats, the request
// will fail the authorization check.
var SupportedDateFormatNames = []string{
	time.RFC822,
	time.RFC822Z,
	time.RFC850,
	time.ANSIC,
	time.RFC1123,
	time.RFC1123Z,
}

// An abstraction that allows test code to easily mock calls to get
// the current time.
var clock = struct{ Now func() time.Time }{Now: time.Now}

// Vangoh is an object that forms the primary point of configuration of the
// middleware HMAC handler. It allows for the configuration of the hashing
// function to use, the headers (specified as regexes) to be included in the
// computed signature, and the mapping between organization tags and the secret
// key providers associated with them.
type Vangoh struct {
	// Indicates if there is one global provider for this HMAC checker. If set to
	// a non-nil pointer to a secretProvider, Vangoh will authenticate all
	// requests against this provider regardless of organization specified in the
	// request's Authorization header.
	singleProvider *secretProvider

	// A map between org tags, as used in the Authentication section, with the
	// secretProvider that provides the identities for that org.
	providersByOrg map[string]secretProvider

	// The hashing function to be used when computing the HMAC hashes.  Common
	// algorithms for HMAC include SHA1, SHA256, and MD5, but any object that
	// implements hash.Hash should work.
	algorithm func() hash.Hash

	// Specifies which headers should be used in computing the HMAC signature for
	// each request.  It is common to have an application-wide prefix for headers
	// to be used, i.e. X-Aur-Meta-User or X-Aur-Locale.  This could be
	// represented with the include header "^X-Aur-".
	includedHeaders map[string]*regexp.Regexp

	// The maximum amount of time that can have passed between the time a request
	// was signed and the time the request was received by the server.
	maxTimeSkew time.Duration

	// Optional custom Date Header to override the default Date Header
	customDateHeader string

	// When true, Handler() includes specific error details in the response when
	// denying incorrectly-authenticated requests.
	debug bool
}

// Creates a new Vangoh instance with no secret providers.
func New() *Vangoh {
	return &Vangoh{
		singleProvider:  nil,
		providersByOrg:  make(map[string]secretProvider),
		algorithm:       crypto.SHA256.New,
		includedHeaders: make(map[string]*regexp.Regexp),
		maxTimeSkew:     time.Minute * 15,
		debug:           false,
	}
}

// Creates a new Vangoh instance that supports a single
// secretProvider. Attempting to add providers with AddProvider will fail with an
// error.
func NewSingleProvider(provider secretProvider) *Vangoh {
	vg := New()
	vg.singleProvider = &provider
	return vg
}

/*
AddProvider sets the secret provider of a specific organization. If the Vangoh
instance was created to use a single provider for all requests, regardless of
organization tag, calling AddProvider will fail and return an error. If the
organization already has a provider, calling AddProvider will fail and return
an error.

By supporting different providers based on org tags, there is the ability to
configure authentication sources based on user type or purpose. For instance,
if an endpoint is going to be used by both a small set of internal services as
well as external users, you could create a different provider for each, as
demonstrated below.

Example:
	func main() {
		// Create provider for internal services credentials (not included with Vangoh).
		internalProvider := providers.NewInMemoryProvider(...)
		// Create provider for normal user credentials (not included with Vangoh).
		userProvider := providers.NewDatabaseProvider(...)

		vg := vangoh.New()
		_ = vg.AddProvider("INT", internalProvider)
		_ = vg.AddProvider("API", userProvider)

		// ...
	}

In this example, any connections made with the authorization header "INT
[userID]:[signature]" will be authenticated against `internalProvider`, and
connections with the header "API [userID]:[signature]" will be authenticated
against `userProvider`.
*/
func (vg *Vangoh) AddProvider(org string, skp secretProvider) error {
	if vg.singleProvider != nil {
		return errors.New("cannot add a provider when created for a single provider")
	}
	if _, ok := vg.providersByOrg[org]; ok {
		return errors.New("cannot add more than one keyProvider for the same org tag")
	}
	vg.providersByOrg[org] = skp
	return nil
}

func (vg *Vangoh) SetAlgorithm(algorithm func() hash.Hash) {
	vg.algorithm = algorithm
}

func (vg *Vangoh) SetDebug(debug bool) {
	vg.debug = debug
}

func (vg *Vangoh) GetDebug() bool {
	return vg.debug
}

/*
IncludeHeader specifies additional headers to include in the construction of
the HMAC signature body for a request.

Given a regex, any non-canonical (e.g. "X-Aur", not "x-aur") headers that match the
regex will be included.

For instance, to match all headers beginning with "X-Aur-", we could include
the header regex "X-Aur-.*".  It is important to note that this funcationality
uses traditional, non-POSIX regular expressions, and will add anchoring to the
provided regex if it is not included.

This means that the regex "X-Aur" will only match headers with key "X-Aur"
exactly.  In order to do prefix matching you must add a wildcard match after,
i.e. "X-Aur.*"
*/
func (vg *Vangoh) IncludeHeader(headerRegex string) error {
	var regexBuf bytes.Buffer
	if !strings.HasPrefix(headerRegex, "^") {
		regexBuf.WriteString("^")
	}
	regexBuf.WriteString(headerRegex)
	if !strings.HasSuffix(headerRegex, "$") {
		regexBuf.WriteString("$")
	}

	regex := regexBuf.String()
	compiled, err := regexp.Compile(regex)
	if err != nil {
		return err
	}
	vg.includedHeaders[regex] = compiled
	return nil
}

/*
SetMaxTimeSkew sets the maximum allowable duration between the date and time specified
in the Date header and the server time when the response is processed.  If the date in
the header exceeds the duration Vangoh will respond to the request with a HTTP status 403 Forbidden.

To match the behavior of AWS (15 minute skew window):
	vg := vangoh.New()
	vg.SetMaxTimeSkew(time.Minute * 15)

When checking the date header, Vangoh follows the precedent of RFC 2616,
accepting dates in any of the following formats:
	ANSIC    = "Mon Jan _2 15:04:05 2006"
	RFC822   = "02 Jan 06 15:04 MST"
	RFC822Z  = "02 Jan 06 15:04 -0700"
	RFC850   = "Monday, 02-Jan-06 15:04:05 MST"
	RFC1123  = "Mon, 02 Jan 2006 15:04:05 MST"
	RFC1123Z = "Mon, 02 Jan 2006 15:04:05 -0700"
*/
func (vg *Vangoh) SetMaxTimeSkew(timeSkew time.Duration) {
	vg.maxTimeSkew = timeSkew
}

func (vg *Vangoh) SetCustomDateHeader(headerName string) {
	vg.customDateHeader = headerName
}

func (vg *Vangoh) getDateHeaderFromRequest(r *http.Request) string {
	dateHeader := ""
	//Use Custom Date header if set
	if vg.customDateHeader != "" {
		dateHeader = strings.TrimSpace(r.Header.Get(vg.customDateHeader))
	}
	//fallback on "Date" header
	if dateHeader == "" {
		dateHeader = strings.TrimSpace(r.Header.Get("Date"))
	}

	return dateHeader
}

// Checks a request for proper authentication details, returning the relevent
// error if the request fails this check or nil if the request passes.
func (vg *Vangoh) AuthenticateRequest(r *http.Request) *AuthenticationError {
	// Parse the ORG, KEY, and SIGNATURE out of the Authorization header.
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader == "" {
		return ErrorAuthHeaderMissing
	}
	match, err := regexp.Match(AuthRegex, []byte(authHeader))
	if err != nil || !match {
		return ErrorAuthHeaderMalformed
	}
	orgSplit := strings.Split(authHeader, " ")
	org := orgSplit[0]
	keySplit := strings.Split(orgSplit[1], ":")
	key := []byte(keySplit[0])
	actualSignatureB64 := keySplit[1]

	// Check that the request was made in the acceptable window.
	dateHeader := vg.getDateHeaderFromRequest(r)
	if dateHeader == "" {
		return ErrorDateHeaderMissing
	}
	date, err := multiFormatDateParse(SupportedDateFormatNames, dateHeader)
	if err != nil {
		return ErrorDateHeaderMalformed
	}
	present := clock.Now()
	if present.Sub(date) > vg.maxTimeSkew || date.Sub(present) > vg.maxTimeSkew {
		return ErrorDateHeaderTooSkewed
	}

	// Load the secret key from the appropriate key provider, given the ID from
	// the Authorization header.
	var provider secretProvider
	if vg.singleProvider != nil {
		provider = *vg.singleProvider
	} else {
		var exists bool
		provider, exists = vg.providersByOrg[org]
		if !exists {
			return ErrorAuthOrgUnknown
		}
	}

	var voidPtr unsafe.Pointer = nil
	var secret []byte

	switch provider := provider.(type) {
	case SecretProviderWithCallback:
		secret, err = provider.GetSecret(key, &voidPtr)
	case SecretProvider:
		secret, err = provider.GetSecret(key)
	}
	if err != nil {
		return ErrorInProviderKeyLookup
	}
	if secret == nil {
		return ErrorSecretNotFound
	}

	// Calculate the b64 signature and compare against the one sent by the client.
	expectedSignature := vg.ConstructSignature(r, secret)
	expectedSignatureB64 := base64.StdEncoding.EncodeToString(expectedSignature)
	if subtle.ConstantTimeCompare([]byte(expectedSignatureB64), []byte(actualSignatureB64)) != 1 {
		return ErrorHMACSignatureMismatch
	}

	switch provider := provider.(type) {
	case SecretProviderWithCallback:
		if voidPtr != nil {
			provider.SuccessCallback(r, &voidPtr)
		} else {
			provider.SuccessCallback(r, nil)
		}
	}
	// If we have made it this far, authentication is successful.
	return nil
}

func (vg *Vangoh) ConstructSignature(r *http.Request, secret []byte) []byte {
	signingString := vg.CreateSigningString(r)
	mac := hmac.New(vg.algorithm, secret)
	mac.Write([]byte(signingString))
	return mac.Sum(nil)
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
CreateSigningString creates the string used for signature generation, in accordance with
the specifications as laid out in the package documentation. Refer there for more detail,
or to the Amazon Signature V2 documentation: http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html.
*/
func (vg *Vangoh) CreateSigningString(r *http.Request) string {
	var buffer bytes.Buffer

	buffer.WriteString(r.Method)
	buffer.WriteString(newline)

	buffer.WriteString(r.Header.Get("Content-MD5"))
	buffer.WriteString(newline)

	buffer.WriteString(r.Header.Get("Content-Type"))
	buffer.WriteString(newline)

	dateHeader := vg.getDateHeaderFromRequest(r)

	buffer.WriteString(dateHeader)
	buffer.WriteString(newline)

	customHeaders := vg.createHeadersString(r)
	buffer.WriteString(customHeaders)

	buffer.WriteString(r.URL.Path)

	return buffer.String()
}

// Create the canonicalized header string part of a request's signature body.
func (vg *Vangoh) createHeadersString(r *http.Request) string {
	if len(vg.includedHeaders) == 0 {
		return ""
	}

	// For each defined regex, determine the set of headers that match. Repeat
	// for all regexes, without duplication, to get the final set of custom
	// headers to use.
	var sanitizedHeaders = make(map[string][]string)

	for _, compiledRegex := range vg.includedHeaders {
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

	// At this point sanitized contains all the headers to be included in the
	// hash. Now we need to retrieve their values, and sanitize them
	// appropriately.
	var buffer bytes.Buffer
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

		// Note that sanitizedValues are unsorted here - the order that they are
		// specified in the header will affect the hash result. This conforms with
		// the standard set by AWS, though it may be more reliable to add this
		// sorting in at some point.
		for i := range sanitizedValues {
			buffer.WriteString(sanitizedValues[i])
			if i < (len(sanitizedValues) - 1) {
				buffer.WriteString(",")
			}
		}

		buffer.WriteString(newline)
	}

	return buffer.String()
}
