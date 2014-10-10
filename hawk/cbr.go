// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

package hawk

import (
	"bytes"
	"errors"
	"io"
)

type closingBytesReader struct {
	io.ReadCloser
	closed bool
	reader *bytes.Reader
}

func NewClosingBytesReader(buffer []byte) *closingBytesReader {
	return &closingBytesReader{
		closed: false,
		reader: bytes.NewReader(buffer),
	}
}

func (cbr *closingBytesReader) Read(p []byte) (n int, err error) {
	if cbr.closed {
		return 0, errors.New("closingBytesReader.Read: Cannot read when closed")
	}
	return cbr.reader.Read(p)
}

func (cbr *closingBytesReader) Close() error {
	cbr.closed = true
	cbr.reader = nil
	return nil
}
