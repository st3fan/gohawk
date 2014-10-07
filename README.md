# Hawk Implementation for Go Servers

*Stefan Arentz, October 2014*

## Introduction

This is a [Hawk](https://github.com/hueniverse/hawk/blob/master/README.md) implementation for web services written in the Go language.It is a simple library that can be embedded in an app without much effort. It is for example used in my [Firefox Sync Server](https://github.com/st3fan/moz-syncserver) project.

> This works has not reached a 1.0 version but it works well for me.  If you find a bug or want a feature, please [file an issue](https://github.com/st3fan/gohawk/issues) for discussion. I am still looking for API simplifications and interesting optional extension points. The project also needs more (integration & functional) tests.

## Basic Usage

In the most simple case you create a `hawk.Authenticator` instance globally or inside a handler context and then call `authenticator.Authenticate()` in your handlers that need Hawk authentication.

The `hawk.Authenticator` takes two services in it's `hawk.NewAuthenticator()` constructor:

* First is a `hawk.CredentialsStore` that is used to retrieve the Hawk key specification for a specific key id. This is where you lookup the algorithm and the secret part for a key with a specified identifier. Since these keys can come from anywhere, there is no default implementation but it is trivial to implement it on top of a datastore.
* The second is an optional `hawk.ReplayChecker` implementation. This service will make sure a request is not submitted twice, preventing replay attacks. The included `MemoryBackedReplayChecker` simply keeps a list of previous Hawk requests in memory. It is trivial to provide an implementation on for example Redis or some shared cache.

### CredentialsStore Example

Here is a very simple example that looks up Hawk keys in a database:

```
type CredentialsStore struct {
   db *sql.DB
}

func (cs *CredentialsStore) CredentialsForKeyIdentifier(keyIdentifier string) (hawk.Credentials, error) {
  var secret string
  err := cs.db.QueryRow("select secret from api_keys where key_id = $1", keyIdentifier).Scan(&secret)
  switch {
    case err == sql.ErrNoRows:
      return nil, nil
    case err != nil:
      return nil, err
    default:
      return hawk.NewBasicCredentials(keyIdentifier, hawk.DefaultAlgorithm, secret), nil
  }
}

db, err := ... connect to a database ...
credentialsStore := &CredentialsStore{db: db}
```

The above example does a straight lookup of a key but you can of course add logic to check for verified or disabled accounts, etc.

### Authenticating Requests

Adding Hawk authentication to your handers is simple: setup a `hawk.Authenticator` and then call `authenticator.Authenticate()` early in your handler.

If you use a web framework that supports middleware then the call to `authenticator.Authenticate()` should be simple to wrap. But even with the `net/http` package this is simple and you may not mind the explicit check.

```
var authenticator = hawk.NewAuthenticator(credentialsStore, hawk.NewMemoryBackedReplayChecker())

func MyHandler(w http.ResponseWriter, r *http.Request) {
  if credentials, ok := authenticator.Authenticate(w, r); ok {
    w.Write("Your are authenticated!")
  }
}
```

In case the authentication fails, `authenticator.Authenticate()` takes care of returning the right HTTP response. There is nothing you need to do in case of errors or failed authentication. Just deal with the success case.

### Custom Credentials

The credentials object is an implementation of the `hawk.Credentials` interface, which has only one required function to return a `hawk.Key`.

```
type Credentials interface {
    Key() Key
}
```

You can very easily make your own implementation that also returns contextual information about the client making the request. For example here is an implementation that also includes a user object in the credentials. It is assumed that your user entities contain some unique id, name and hawk key information.

```
type User struct {
  Id int
  Name string
  HawkKeyIdentifier string
  HawkKey []byte
}

type Credentials struct {
  User User
}

func (c *MyCredentials) Key() hawk.Key {
  return hawk.NewBasicCredentials(c.user.HawkKeyIdentifier, hawk.DefaultAlgorithm, c.user.HawkKey)
}

func GetHawkCredentials(r *http.Request, keyIdentifier string) (hawk.Credentials, error) {
  user, err := lookupUserByKeyIdentifier(keyIdentifier)
  if user == nil || err != nil {
    if err != nil {
      return nil, err
    } else {
      return nil, nil
    }
  }
  return &Credentials{user: user}
}
```

This does mean you have to cast the credentials to your own type in your handler:

```
func MyHandler(w http.ResponseWriter, r *http.Request) {
  if cr, ok := authenticator.Authenticate(w, r); ok {
    credentials := cr.(*Credentials)
    w.Write([]byte("Hello, " + credentials.user.Name "!"))
  }
}
```

If you have a lot of handlers then you can simply wrap most of this in a convenience function similar to `Authenticate()` that returns your custom `Credentials` type.
