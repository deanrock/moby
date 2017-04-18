package tarexport

import (
	"bufio"
	"io"
)

type bufferedReadCloser struct {
	r *bufio.Reader
	io.ReadCloser
}

func (b bufferedReadCloser) Peek(n int) ([]byte, error) {
	return b.r.Peek(n)
}

func (b bufferedReadCloser) Read(p []byte) (int, error) {
	return b.r.Read(p)
}
