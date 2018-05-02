package bsftp

import "github.com/pkg/errors"

var (
	shortPacketError           = errors.New("Packet too short")
	unknownExtendedPacketError = errors.New("Unknown extended packet")
)