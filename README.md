Server-Side Hawk Implementation for Go projects.


## Basic Usage

In the most simple case you create a `hawk.Authorizer` instance globally or inside a handler context and then call `authorizer.Authorize()` in your handlers that need Hawk authentication.

The `hawk.Authorizer` takes two values with it's `hawk.NewAuthorizer()` constructor:

* First is a callback function that is called to retrieve the Hawk key specification for a specific key id, containing the algorithm and the secret part of the key.
* The second is an optional `hawk.ReplayChecker` implementation that lets you prevent replay attachs. The includes `MemoryBackedReplayChecker` simply keeps a list of previous Hawk requests in memory.

```
func GetHawkCredentials(r *http.Request, keyIdentifier string) (hawk.Credentials, error) {
  return hawk.NewBasicCredentials(keyIdentifier, "sha256",
      "secretkeycheesebaconeggs"), nil
}

var hawkAuthorizer = hawk.NewAuthorizer(GetHawkCredentials,
    hawk.NewMemoryBackedReplayChecker())
```

Your handlers looks similar to this. If you use a web framework that supports middleware then the call to `Authorize()` should be simple to wrap. Personally I keep things simple and I don't mind the verbosity of a the implementation below:

```
func MyHandler(w http.ResponseWriter, r *http.Request) {
  if credentials, ok := hawkAuthorizer.Authorize(w, r); ok {
    w.Write("Your are authenticated!")
  }
}
```

In case the authorization fails, `authorizer.Authorize()` takes care of returning the right HTTP response. There is nothing you need to do, except deal with the success case.

The credentials object is an implementation of of the `hawk.Credentials` interface, which has only one required function to return the Hawk Key. You can very easily make your own implementation that also contains information about the user making the request:

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
  if credentials, ok := hawkAuthorizer.Authorize(w, r); ok {
    myCredentials := credentials.(*MyCredentials)
    w.Write("Your are authenticated " + myCredentials.user.Name)
  }
}
```
