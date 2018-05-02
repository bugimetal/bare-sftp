package bsftp

import (
	"io"
	"sync"
)

type connection struct {
	io.Reader
	io.WriteCloser
	sync.Mutex
}