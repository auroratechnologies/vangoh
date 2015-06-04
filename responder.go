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
	status  int
	message string
	title   string
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
	rw.WriteHeader(r.status)
}

var missingHeader = &responder{
	http.StatusBadRequest,
	fmt.Sprintf("Missing %v Header", HMACHeader),
	fmt.Sprintf("You must supply the %q header to this endpoint", HMACHeader),
}

var malformedHmacHeader = &responder{
	http.StatusBadRequest,
	fmt.Sprintf("Malformed %v Header", HMACHeader),
	fmt.Sprintf(
		"The value supplied as the %q header must of the format "+
			"[ORG] [accesID]:[signature]", HMACHeader),
}

var malformedDateHeader = &responder{
	http.StatusBadRequest,
	fmt.Sprintf("Invalid date format"),
	fmt.Sprintf(
		"The format of the Date header is not in a format able to be parsed by " +
			"the server"),
}

var timeSkewTooLarge = &responder{
	http.StatusForbidden,
	fmt.Sprintf("Time too skewed"),
	fmt.Sprintf(
		"The value supplied as the Date header is too skewed from the system " +
			"time"),
}

var invalidOrgTag = &responder{
	http.StatusBadRequest,
	"Invalid Org Tag",
	fmt.Sprintf("The org tag specified in %q header is invalid", HMACHeader),
}

var signatureWrongSize = &responder{
	http.StatusBadRequest,
	"Signature Wrong Size",
	"The length of the HMAC signature must exactly match the output of the " +
		"algorithm in use. Check to make sure your algorithm matches that in " +
		"use on the server.",
}

var unableToAuthenticate = &responder{
	http.StatusForbidden,
	"Unable to Authenticate",
	"The request you have made was unable to be authenticated",
}

var keyLookupFailure = &responder{
	http.StatusInternalServerError,
	"Key Lookup Failure",
	"Failure while attempting to lookup the secret key for the provided " +
		"access ID",
}

var signingFailure = &responder{
	http.StatusInternalServerError,
	"Signing Failure",
	"Error encountered when attempting to generate the signing string to " +
		"be hashed",
}
