// Package vangoh (stylized as VanGoH) is a library designed to easily enable go
// web servers to be secured using HMAC authentication.
//
// VanGoH stands for Vanilla Go HMAC, and it is just that.  It makes use of nothing
// apart from the Go core libraries to provide a robust and flexible solution
// for adding HMAC request authentication to a new or pre-existing web stack.
//
// It was designed to implement the HMAC scheme that was popularized by Amazon's AWS
// as described in detail here - http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html
//
// The primary characteristic of this implementation is that the signature is placed
// In the "Authorization" header, along with the access ID, and a tag for the organization.
//
// Apart from implementing the signature-computing scheme defined by AWS, VanGoH also includes
// support for multiple different secret key providers within one instance, allowing flexibility
// in how different users and requests are authenticated.  In addition, VanGoH allows for
// choice in the hashing algorithm that your HMAC implementation uses.  The constructors
// default the algorithm used to SHA256, but it can be easily configured to support any
// class that implements hash.Hash
//
// VanGoH is designed to fit in with the conventions of the net/http package, meaning
// that integration with middleware stacks is easy, regardless of other software in use.
package vangoh

//
// TODO: Add more detailed usage documentation
//
