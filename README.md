VanGoH [![GoDoc](https://godoc.org/github.com/auroratechnologies/vangoh?status.svg)](https://godoc.org/github.com/auroratechnologies/vangoh)
======

######The Vanilla Go HMAC handler

VanGoH implements the HMAC authentication scheme popularized by [Amazon's AWS](http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html).

In order to compute and check the HMAC signature, it utilizes the Authorization header in the format:

    Authorization: [ORG] [accessID]:[HMACSignature]

Where:
 - [ORG] is the organization tag, representing the company or API to be connected to
 - [accessID] is the unique, public identifier of the user or service, such as a username or API key
 - [HMACSignature] is the HMAC-produced signature for the request.

Much like the AWS HMAC implementation, VanGoH allows for specifying additional headers to be used when calculating the hash, and incorporates the Date header to assist in identifying duplicate requests.

There is also support of separate authentication sources for multiple organizational tags, permitting varying authentication for standard users vs. privileged API access.  An internal service making several requests may authenticate through an in-memory map, for instance, while a standard user request may authenticate through a less performant but more scalable database lookup of their private key.

VanGoH was designed to conform to the net/http package, meaning that it should slot in easily to any existing web stack.

###Full example
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

// A SecretKeyProvider must implement the GetSecretKey method.  In this case it's a simple
// in-memory map, tho it could easily be a database connection or something of that ilk
func (imkp *inMemoryKeyProvider) GetSecretKey(identifier []byte) ([]byte, error) {
  key, found := imkp.keyMap[string(identifier)]
  if !found {
    // Returning nil, nil indicates to VanGoH that key was not found
    return nil, nil
  }
  return key, nil
}

// Any net/http handler or handlerFunc that you want
var baseHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
  fmt.Fprintln(w, "Hello, Secret World!")
})

func main() {
  // Declaring the in memory map of user IDs to Secret Keys
  var userMap = make(map[string][]byte)
  userMap["exampleUserID"] = []byte("SUPERSECRETEXAMPLEKEY")

  // Making our example SecretKeyProvider with the map
  userProvider := &inMemoryKeyProvider{
    keyMap: userMap,
  }

  // Creating out new VanGoH instance
  vg := vangoh.New()
  // Setting the hashing algorithm to SHA-1
  vg.SetAlgorithm(crypto.SHA1.New)
  // Linking the "AWS" organization tag to the example SecretKeyProvider
  vg.AddProvider("AWS", userProvider)
  // Adding the custom headers (as a regex) that we want to include in our signature computation
  vg.IncludeHeader("^x-aws-.*")

  // Route the handler through VanGoH, and ListenAndServer as usual
  app := vg.Handler(baseHandler)
  http.ListenAndServe("0.0.0.0:3000", app)
}
```

And with that we have completely replicated the authentication procedure used by AWS!

Full package and usage documentation can be located at [the godocs site](https://godoc.org/github.com/auroratechnologies/vangoh).
