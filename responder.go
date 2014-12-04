package vangoh

import "net/http"
import "fmt"

/*
responder is a utility class for VanGoH, used for generating and formatting appropriate
http responses in the event of an error.  Nothing within this class is exported with
the package, as it is only meant for internal use.

The base design of this utility class was influenced by schnellburger, by hydrogen18 -
https://github.com/hydrogen18/schnellburger
*/
type responder struct {
	status        int
	message       string
	title         string
	detailedError error
}

func newResponder(status int, title string, message string) *responder {
	r := &responder{
		status:        status,
		title:         title,
		message:       message,
		detailedError: nil,
	}
	return r
}

func (r *responder) setError(err error) *responder {
	r.detailedError = err
	return r
}

/*
All custom headers for responses begin with the prefix "Hmac-"

They do not begin with "X-", in accordance to the deprecation of the convention
in RFC 6684 - http://tools.ietf.org/html/rfc6648
*/

//Header returned to indicate what algorithm the server is using to validate requests
const algorithmHeader = "Hmac-Algorithm"

//Header returned with a summary of the error encountered
const errorTitleHeader = "Hmac-Error-Title"

//Header returned with a more moderately detailed error message
const errorMessageHeader = "Hmac-Error-Message"

/*
Utility function to format and write a response to a request, given an error
*/
func (r *responder) respond(rw http.ResponseWriter, req *http.Request, vg VanGoH) {
	rw.Header().Add(algorithmHeader, fmt.Sprintf("%T", vg.algorithm()))
	rw.Header().Add(errorTitleHeader, r.title)
	rw.Header().Add(errorMessageHeader, r.message)

	rw.Header().Add("Content-Type", "text/plain")
	rw.WriteHeader(r.status)

	fmt.Fprintf(rw, "%s\n---\n%s\n", r.title, r.message)
	if r.detailedError != nil {
		fmt.Fprintf(rw, "===\nDetailed error message\n---\n%s\n", r.detailedError.Error())
	}
}

var missingHeader = newResponder(http.StatusBadRequest,
	fmt.Sprintf("Missing %v Header", HMACHeader),
	fmt.Sprintf("You must supply the %q header to this endpoint", HMACHeader))

var malformedHeader = newResponder(http.StatusBadRequest,
	fmt.Sprintf("Malformed %v Header", HMACHeader),
	fmt.Sprintf("The value supplied as the %q header must of the format [ORG] [accesID]:[signature]", HMACHeader))

var invalidOrgTag = newResponder(http.StatusBadRequest, "Invalid Org Tag",
	fmt.Sprintf("The org tag specified in %q header is invalid", HMACHeader))

var signatureWrongSize = newResponder(http.StatusBadRequest, "Signature Wrong Size",
	"The length of the HMAC signature must exactly match the output of the algorithm in use.  "+
		"Check to make sure your algorithm matches that in use on the server.")

var unableToAuthenticate = newResponder(http.StatusForbidden, "Unable to Authenticate",
	"The request you have made was unable to be authenticated")

var keyLookupFailure = newResponder(http.StatusInternalServerError, "Key Lookup Failure",
	"Failure while attempting to lookup the secret key for the provided access ID")

var signingFailure = newResponder(http.StatusInternalServerError, "Signing Failure",
	"Error encountered when attempting to generate the signing string to be hashed")
