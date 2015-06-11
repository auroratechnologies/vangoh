Vangoh [![GoDoc](https://godoc.org/github.com/auroratechnologies/vangoh?status.svg)](https://godoc.org/github.com/auroratechnologies/vangoh)
======

######The Vanilla Go HMAC handler


Vangoh implements the HMAC authentication scheme popularized by [Amazon's AWS](http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html).

In order to compute and check the HMAC signature, it checks the details included in a request's `Authorization` header. It expects them to be in the form

```
Authorization: [ORG] [KEY]:[HMAC_SIGNATURE]
```

Where:
 - `[ORG]` is the organization tag, e.g., `AWS`.
 - `[KEY]` is the unique, public identifier of the user or service, such as a username or API key, e.g., `EKsZs7eRe9z3q79KsZmoK1plHAB0UC`.
 - `[HMACSignature]` is the base64-encoded HMAC signature of various details of the request, e.g., `44IVL7XT3zqe2+/6tUbe39Da4Hq2MK==`.

Much like the AWS HMAC implementation, Vangoh allows for specifying additional headers to be used when calculating the hash, and incorporates the Date header to assist in identifying duplicate requests. Read the [AWS documentation](http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html) and the code to see the details of constructing the signature.

There is also support of separate authentication sources for multiple organizational tags, permitting varying authentication for standard users vs.  privileged API access. An internal service making several requests may authenticate through an in-memory map, for instance, while a standard user request may authenticate through a less performant but more scalable database lookup of their private key.

Vangoh was designed to conform to the `net/http` package, and includes two "middleware"-esque functions (`vangoh.Handler`, `vangoh.NegroniHandler`) for easy integration with your existing code.


### Documentation
Full documentation is [hosted at Godoc](https://godoc.org/github.com/auroratechnologies/vangoh).


### Example usage
```go
package main

import (
  "crypto"
  _ "crypto/sha1"
  "fmt"
  "net/http"

  "github.com/auroratechnologies/vangoh"
)

type inMemoryKeyProvider struct {
  keyMap map[string][]byte
}

// A SecretProvider must implement the GetSecret method. In this case it's a
// simple in-memory map, although it could easily be a database connection or
// any other implementation.
func (imkp *inMemoryKeyProvider) GetSecretKey(identifier []byte) ([]byte, error) {
  key, found := imkp.keyMap[string(identifier)]
  if !found {
    // Returning nil, nil indicates to Vangoh that key was not found
    return nil, nil
  }
  return key, nil
}

// Any net/http handler or handlerFunc that you want
var apiEndpoint = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
  w.WriteHeader(http.StatusOK)
  fmt.Fprintln(w, "Hello, authenticated world!")
})

func main() {
  // Declaring the in memory map of user IDs to Secret Keys
  var userMap = make(map[string][]byte)
  userMap["exampleUserID"] = []byte("SUPERSECRETEXAMPLEKEY")

  // Making our example SecretKeyProvider with the map
  userProvider := &inMemoryKeyProvider{
    keyMap: userMap,
  }

  // Creating our new Vangoh instance
  vg := vangoh.New()
  // Setting the hashing algorithm to SHA-1
  vg.SetAlgorithm(crypto.SHA1.New)
  // Linking the "EXMP" organization tag to the example SecretProvider
  _ = vg.AddProvider("EXMP", userProvider)
  // Adding the custom headers (as a regex) that we want to include in our
  // signature computation.
  vg.IncludeHeader("^X-Exmp-.*")

  // Route the handler through Vangoh, and ListenAndServer as usual
  app := vg.Handler(apiEndpoint)
  http.ListenAndServe("0.0.0.0:3000", app)
}
```

And with that we have replicated the core authentication procedure used by AWS!

