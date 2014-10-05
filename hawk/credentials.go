// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

package hawk

type Credentials interface {
	Key() Key
}

type BasicCredentials struct {
	key Key
}

func NewBasicCredentials(identifier string, secret []byte, algorithm Algorithm) *BasicCredentials {
	return &BasicCredentials{
		key: Key{
			Identifier: identifier,
			Secret:     secret,
			Algorithm:  algorithm,
		},
	}
}

func NewBasicCredentialsWithKey(key Key) *BasicCredentials {
	return &BasicCredentials{key: key}
}

func (c *BasicCredentials) Key() Key {
	return c.key
}

type CredentialsStore interface {
	CredentialsForKeyIdentifier(keyIdentifier string) (Credentials, error)
}
