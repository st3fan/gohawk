# Server-Side Hawk Implementation for Go projects

Used in for example my [Firefox Sync Server](https://github.com/st3fan/moz-syncserver) implementation.

## Basic Usage

In the most simple case you create a `hawk.Authenticator` instance globally or inside a handler context and then call `authorizer.Authenticate()` in your handlers that need Hawk authentication.

The `hawk.Authenticator` takes two values with it's `hawk.NewAuthenticator()` constructor:

* First is a callback function that is called to retrieve the Hawk key specification for a specific key id, containing the algorithm and the secret part of the key.
* The second is an optional `hawk.ReplayChecker` implementation that lets you prevent replay attacks. The included `MemoryBackedReplayChecker` simply keeps a list of previous Hawk requests in memory. It is trivial to provide an implementation on for example Redis or some shared cache.

```
// A basic key retrieval function that returns a static key
func GetHawkCredentials(r *http.Request, keyId string) (hawk.Credentials, error) {
  return hawk.NewBasicCredentials(keyId, "sha256", "secretkeylalala"), nil
}

var hawkAuthenticator = hawk.NewAuthenticator(GetHawkCredentials,
    hawk.NewMemoryBackedReplayChecker())
```

Your handlers will look as follows. If you use a web framework that supports middleware then the call to `Authenticate()` should be simple to wrap. Personally I keep things simple with the `net/http` package and I don't mind the verbosity of an explicit check.

```
func MyHandler(w http.ResponseWriter, r *http.Request) {
  if credentials, ok := hawkAuthenticator.Authenticate(w, r); ok {
    w.Write("Your are authenticated!")
  }
}
```

In case the authorization fails, `authorizer.Authenticate()` takes care of returning the right HTTP response. There is nothing you need to do, except to deal with the success case.

The credentials object is an implementation of the `hawk.Credentials` interface, which has only one required function to return a `hawk.Key` that maps to the current request.

You can very easily make your own implementation that also contains information about the user making the request. For example here is an implementation that also includes a user object in the credentials.

```
type MyUser struct {
  Id int
  Name string
  HawkKeyIdentifier string
  HawkKey string
}

type MyCredentials struct {
  user MyUser
}

func (c *MyCredentials) Key() hawk.Key {
  return hawk.NewBasicCredentials(c.user.HawkKeyIdentifier, "sha256", c.user.HawkKey), 
}

func GetHawkCredentials(r *http.Request, keyIdentifier string) (hawk.Credentials, error) {
    user, err := lookupUserByKeyIdentifier(keyIdentifier)
    if user == nil || err != nil {
      return user, err
    }
    return &MyCredentials{user: user}
}
```

This does mean you have to cast the credentials to your own type in your handler:

```
func MyHandler(w http.ResponseWriter, r *http.Request) {
  if credentials, ok := hawkAuthenticator.Authenticate(w, r); ok {
    myCredentials := credentials.(*MyCredentials)
    w.Write("Your are authenticated " + myCredentials.user.Name)
  }
}
```
