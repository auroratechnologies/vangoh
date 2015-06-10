package vangoh

/*
A SecretProvider is an interface implementing a method to look up a secret
given a public identifier, commonly referred to as a key (as in, key + secret
authentication.)

The interface allows for flexibility; the implementaiton could be a map, or a
function that does a lookup in a database.

Errors returned are to be returned from GetSecretKey only in the event that an
actual error is encountered by the provider (I/O error, timeout, etc.).  In
this case, Vangoh will respond to the request with HTTP code 500 Internal
Server Error.

If the identifier cannot be found by the key provider, expected behavior is to
return nil, nil; no secret was found, and no error was encountered. Vangoh will
respond to the request with HTTP code 403 Forbidden.
*/
type SecretProvider interface {
	GetSecret(key []byte) ([]byte, error)
}
