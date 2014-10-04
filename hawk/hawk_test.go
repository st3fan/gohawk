// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

package hawk

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
)

func Test_parseParameters(t *testing.T) {
	parameters, err := parseParameters(`id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", hash="Yi9LfIIFRtBEPt74PVmbTF/xVAwPn7ub15ePICfgnuY=", ext="some-app-ext-data", mac="aSe1DERmZuRl3pI36/9BdZmnErTw3sNzOOAUlfeKjVw="`)
	if err != nil {
		t.Error("Cannot parse Hawk parameters", err)
	}

	if parameters.Id != "dh37fgj492je" {
		t.Error("id mismatch")
	}

	if parameters.Timestamp != 1353832234 {
		t.Error("ts mismatch")
	}

	if parameters.Nonce != "j4h3g2" {
		t.Error("nonce mismatch")
	}

	if parameters.Ext != "some-app-ext-data" {
		t.Error("ext mismatch")
	}

	expectedHash, _ := hex.DecodeString("622f4b7c820546d0443edef83d599b4c5ff1540c0f9fbb9bd7978f2027e09ee6")
	if !bytes.Equal(parameters.Hash, expectedHash) {
		t.Error("mac mismatch")
	}

	expectedMac, _ := hex.DecodeString("6927b50c446666e465de9237ebff417599a712b4f0dec37338e01495f78a8d5c")
	if !bytes.Equal(parameters.Mac, expectedMac) {
		t.Error("mac mismatch")
	}
}

func Test_validateParameters(t *testing.T) {
}

func Test_getRequestHost(t *testing.T) {
	test := func(url string, expectedHost string, headers map[string]string) {
		request, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Error(err)
		}
		host := getRequestHost(request)
		if host != expectedHost {
			t.Errorf("Expected host %s for %s but got %s", expectedHost, url, host)
		}
	}
	test("http://localhost/foo", "localhost", nil)
	test("https://127.0.0.1/foo", "127.0.0.1", nil)
	test("http://localhost:8080/foo", "localhost", nil)
	test("https://127.0.0.1:8443/foo", "127.0.0.1", nil)
	// TODO: Add tests here that mimic a typical front proxy (X-Forwarded-Proto?)
	test("http://localhost/foo", "localhost", map[string]string{})
	test("https://127.0.0.1/foo", "127.0.0.1", map[string]string{})
	test("http://localhost:8080/foo", "localhost", map[string]string{})
	test("https://127.0.0.1:8443/foo", "127.0.0.1", map[string]string{})
}

func Test_getRequestPort(t *testing.T) {
	test := func(url string, expectedPort int) {
		request, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Error(err)
		}
		port := getRequestPort(request)
		if port != expectedPort {
			t.Errorf("Expected port %d for %s but got %d", expectedPort, url, port)
		}
	}
	test("http://localhost/foo", 80)
	test("https://localhost/foo", 443)
	test("http://localhost:8080/foo", 8080)
	test("https://localhost:8443/foo", 8443)
}

func Test_calculatePayloadHash(t *testing.T) {
	r, err := http.NewRequest("POST", "http://localhost", strings.NewReader("Thank you for flying Hawk"))
	if err != nil {
		t.Error(err)
	}
	r.Header.Add("Content-Type", "text/plain")
	hash, err := calculatePayloadHash(r)
	if err != nil {
		t.Error(err)
	}
	expectedHash, _ := base64.StdEncoding.DecodeString("Yi9LfIIFRtBEPt74PVmbTF/xVAwPn7ub15ePICfgnuY=")
	if !bytes.Equal(hash, expectedHash) {
		t.Error("Hash mismatch")
	}
}

func Test_calculateRequestSignatureWithGET(t *testing.T) {
	r, err := http.NewRequest("GET", "http://example.com:8000/resource/1?b=1&a=2", nil)
	if err != nil {
		t.Error(err)
	}

	parameters := Parameters{
		Timestamp: 1353832234,
		Ext:       "some-app-ext-data",
		Nonce:     "j4h3g2",
		Hash:      nil,
		// TODO: Rest is not important for this test
	}

	credentials := Credentials{
		KeyIdentifier: "dh37fgj492je",
		Key:           []byte("werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn"),
		Algorithm:     "sha256",
	}

	mac, err := calculateRequestSignature(r, parameters, credentials)
	if err != nil {
		t.Error(err)
	}

	expectedMac, _ := base64.StdEncoding.DecodeString("6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE=")
	if !bytes.Equal(mac, expectedMac) {
		t.Error("Mac mismatch")
	}
}

func Test_calculateRequestSignatureWithPOST(t *testing.T) {
	r, err := http.NewRequest("POST", "http://example.com:8000/resource/1?b=1&a=2", strings.NewReader("Thank you for flying Hawk"))
	if err != nil {
		t.Error(err)
	}
	r.Header.Add("Content-Type", "text/plain")

	payloadHash, _ := base64.StdEncoding.DecodeString("Yi9LfIIFRtBEPt74PVmbTF/xVAwPn7ub15ePICfgnuY=")

	parameters := Parameters{
		Timestamp: 1353832234,
		Ext:       "some-app-ext-data",
		Nonce:     "j4h3g2",
		Hash:      payloadHash,
		// TODO: Rest is not important for this test
	}

	credentials := Credentials{
		KeyIdentifier: "dh37fgj492je",
		Key:           []byte("werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn"),
		Algorithm:     "sha256",
	}

	mac, err := calculateRequestSignature(r, parameters, credentials)
	if err != nil {
		t.Error(err)
	}

	expectedMac, _ := base64.StdEncoding.DecodeString("aSe1DERmZuRl3pI36/9BdZmnErTw3sNzOOAUlfeKjVw=")
	if !bytes.Equal(mac, expectedMac) {
		t.Error("Mac mismatch")
	}
}
