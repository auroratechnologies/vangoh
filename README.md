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

Full package and usage documentation can be located at [the godocs site](https://godoc.org/github.com/auroratechnologies/vangoh).
