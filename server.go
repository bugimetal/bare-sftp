package bsftp

import (
	"io"
	"os"
	"sync"
)

const (
	SftpServerWorkerCount = 8
	MaxTxPacketSize = 1 << 15
)

type Server struct {
	*connection
	openFiles     map[string]*os.File
	openFilesLock sync.RWMutex
	handleCount   int
	rootDirectory string
}

type ServerOption func(*Server) error

func RootDirectory(root string) ServerOption {
	return func(s *Server) error {
		s.rootDirectory = root
		return nil
	}
}

func NewServer(rwc io.ReadWriteCloser, options ...ServerOption) (*Server, error) {
	conn := &connection{
		Reader:      rwc,
		WriteCloser: rwc,
	}
	server := &Server{
		connection: conn,
		openFiles:  make(map[string]*os.File),
	}

	for _, option := range options {
		if err := option(server); err != nil {
			return nil, err
		}
	}

	return server, nil
}