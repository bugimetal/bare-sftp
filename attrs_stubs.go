// +build !cgo,!plan9 windows android

package bsftp

import (
	"os"
)

func fileStatFromInfoOs(fi os.FileInfo, flags *uint32, fileStat *FileStat) {
	// todo
}