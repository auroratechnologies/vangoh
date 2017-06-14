package vangoh

import (
	"net/http"
)

/*
A secretProvider is an interface implementing a method to look up a secret
given a public identifier, commonly referred to as a key (as in, key + secret
authentication.)

The interface allows for flexibility; the implementation could be a map, or a
function that does a lookup in a database.

Errors should only be returned from GetSecret in the event that an actual error
is encountered by the provider (I/O error, timeout, etc.). In this case,
Vangoh will respond to the request with HTTP code 500 Internal Server Error.

If the provider can find no secret associated with the given key, the provider
should return nil, nil (no secret was found, and no error was encountered.) In
this case, Vangoh will respond to the request with HTTP code 403 Forbidden.
*/
type secretProvider interface{}

/*
A SecretProvider only needs to implement the secret lookup method as described
above.
*/
type SecretProvider interface {
	secretProvider
	GetSecret(key []byte) ([]byte, error)
}

/*

The SecretProviderWithCallback interface allows providers to access the request
and any data they might want to store as part of the call to GetSecret. This is
useful for avoiding duplicate access to expensive resource. For example, if the
call to GetSecret fetches some sort of "session" or "user" object from a
database, and the request authenticates successfully, the provider can now
associate that "session" or "user" with the request, avoiding a duplicate
lookup.

Example:
	type customProvider struct {
		database someDatabaseConnectionType
	}
	type customProviderData struct {
		User UserDBModel
	}
	func (p *customProvider) GetSecret(key []byte, cbPayload *CallbackPayload) ([]byte, error) {
		user, err := database.GetUserByKey(key)
		if err != nil {
			return nil, err
		}
		if user == nil {
			return nil, nil
		}
		data := &customProviderData{User: user}
		cbPayload.SetPayload(data)
		return user.Secret, nil
	}

	func (p *customProvider) SuccessCallback(r *http.Request, cbPayload *CallbackPayload) {
		data, ok := cbPayload.Payload.(*customProviderData)
		if !ok {
			panic(errors.New("Unexpected payload found in callbackPayload"))
		}
		context.Set(r, UserContextKey, data.User)
	}
*/

type CallbackPayload struct {
	payload interface{}
}

func (c *CallbackPayload) SetPayload(p interface{}) {
	c.payload = p
}

func (c *CallbackPayload) GetPayload() interface{} {
	return c.payload
}

type SecretProviderWithCallback interface {
	secretProvider
	GetSecret(key []byte, cbPayload *CallbackPayload) ([]byte, error)
	SuccessCallback(r *http.Request, cbPayload *CallbackPayload)
}
