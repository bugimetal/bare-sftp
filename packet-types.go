package bsftp

import "encoding"

const (
	SSH_FXP_INIT           = 1
    SSH_FXP_VERSION        = 2
    SSH_FXP_OPEN           = 3
    SSH_FXP_CLOSE          = 4
    SSH_FXP_READ           = 5
    SSH_FXP_WRITE          = 6
    SSH_FXP_LSTAT          = 7
    SSH_FXP_FSTAT          = 8
    SSH_FXP_SETSTAT        = 9
    SSH_FXP_FSETSTAT       = 10
    SSH_FXP_OPENDIR        = 11
    SSH_FXP_READDIR        = 12
    SSH_FXP_REMOVE         = 13
    SSH_FXP_MKDIR          = 14
    SSH_FXP_RMDIR          = 15
    SSH_FXP_REALPATH       = 16
    SSH_FXP_STAT           = 17
    SSH_FXP_RENAME         = 18
    SSH_FXP_READLINK       = 19
    SSH_FXP_SYMLINK        = 20
    SSH_FXP_STATUS         = 101
    SSH_FXP_HANDLE         = 102
    SSH_FXP_DATA           = 103
    SSH_FXP_NAME           = 104
    SSH_FXP_ATTRS          = 105
    SSH_FXP_EXTENDED       = 200
	SSH_FXP_EXTENDED_REPLY = 201
)
type sshFXPPacket struct {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	PacketLength uint32
	PacketType   byte
}


type extensionPair struct {
	ExtensionName string
	ExtensionData string
}
type sshFXPInitPacket struct {
	sshFXPPacket
	Version    uint32
	Extensions []extensionPair
}

func (p sshFXPInitPacket) MarshalBinary() ([]byte, error) {
	b:= makePacketHeader(SSH_FXP_INIT, p.Version, p.Extensions)
	b = marshalUint32(b, p.Version)
	return marshalExtensions(b, p.Extensions), nil
}

func (p *sshFXPInitPacket) UnmarshalBinary(b []byte) error {
	var err error
	p.Version, b, err = unmarshalUint32Safe(b)	
	return err
}


type sshFXPVersionPacket struct {
	sshFXPPacket
	Version    uint32
	Extensions []extensionPair
}

func (p sshFXPVersionPacket) MarshalBinary() ([]byte, error) {
	b:= makePacketHeader(SSH_FXP_VERSION, p.Version, p.Extensions)
	b = marshalUint32(b, p.Version)
	return marshalExtensions(b, p.Extensions), nil
}

func (p *sshFXPVersionPacket) UnmarshalBinary(b []byte) error {
	var err error
	p.Version, b, err = unmarshalUint32Safe(b)	
	return err
}


const (
	SSH_FXF_READ   = 0x00000001
    SSH_FXF_WRITE  = 0x00000002
    SSH_FXF_APPEND = 0x00000004
    SSH_FXF_CREAT  = 0x00000008
    SSH_FXF_TRUNC  = 0x00000010
    SSH_FXF_EXCL   = 0x00000020
)
type sshFXPOpenPacket struct {
	sshFXPPacket
	ID       uint32
	Filename string
	PFlags   uint32
	Attrs    fileAttributes
}

func (p sshFXPOpenPacket) MarshalBinary() ([]byte, error) {
	b := makePacketHeader(SSH_FXP_OPEN, p.ID, p.Filename, p.PFlags, p.Attrs)
	b = marshalUint32(b, p.ID)
	b = marshalString(b, p.Filename)
	b = marshalUint32(b, p.PFlags)
	return marshalFileAttributes(b, p.Attrs), nil
}

func (p *sshFXPOpenPacket) UnmarshalBinary(b []byte) error {
	var err error
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil { return err }
	if p.Filename, b, err = unmarshalStringSafe(b); err != nil { return err }
	if p.PFlags, b, err = unmarshalUint32Safe(b); err != nil { return err }
	p.Attrs, b, err = unmarshalFileAttributesSafe(b)
	return err
}


type sshFXPHandlePacket struct {
	sshFXPPacket
	ID     uint32
	Handle string
}

func (p sshFXPHandlePacket) MarshalBinary() ([]byte, error) {
	b := makePacketHeader(SSH_FXP_HANDLE, p.ID, p.Handle)
	b = marshalUint32(b, p.ID)
	return marshalString(b, p.Handle), nil
}

func (p *sshFXPHandlePacket) UnmarshalBinary(b []byte) error {
	var err error
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil { return err }
	p.Handle, b, err = unmarshalStringSafe(b)
	return err
}


type sshFXPStatusPacket struct {
	sshFXPPacket
	ID           uint32
	StatusCode   uint32
	ErrorMessage string
	LanguageTag  string
}

func (p sshFXPStatusPacket) MarshalBinary() ([]byte, error) {
	b := makePacketHeader(SSH_FXP_STATUS, p.ID, p.StatusCode, p.ErrorMessage, "en-us")
	b = marshalUint32(b, p.ID)
	b = marshalUint32(b, p.StatusCode)
	b = marshalString(b, p.ErrorMessage)
	return marshalString(b, "en-us"), nil
}

func (p *sshFXPStatusPacket) UnmarshalBinary(b []byte) error {
	var err error
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil { return err }
	if p.StatusCode, b, err = unmarshalUint32Safe(b); err != nil { return err }
	if p.ErrorMessage, b, err = unmarshalStringSafe(b); err != nil { return err }
	p.LanguageTag, b, err = unmarshalStringSafe(b)
	return err
}


type sshFXPClosePacket struct {
	sshFXPPacket
	ID     uint32
	Handle string
}

func (p sshFXPClosePacket) MarshalBinary() ([]byte, error) {
	b := makePacketHeader(SSH_FXP_CLOSE, p.ID, p.Handle)
	b = marshalUint32(b, p.ID)
	return marshalString(b, p.Handle), nil
}

func (p *sshFXPClosePacket) UnmarshalBinary(b []byte) error {
	var err error
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil { return err }
	p.Handle, b, err = unmarshalStringSafe(b)
	return err
}


type sshFXPReadPacket struct {
	sshFXPPacket
	ID     uint32
	Handle string
	Offset uint64
	Len    uint32
}

func (p sshFXPReadPacket) MarshalBinary() ([]byte, error) {
	b := makePacketHeader(SSH_FXP_READ, p.ID, p.Handle)
	b = marshalUint32(b, p.ID)
	b = marshalString(b, p.Handle)
	b = marshalUint64(b, p.Offset)
	return marshalUint32(b, p.Len), nil
}

func (p *sshFXPReadPacket) UnmarshalBinary(b []byte) error {
	var err error
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil { return err }
	if p.Handle, b, err = unmarshalStringSafe(b); err != nil { return err }
	if p.Offset, b, err = unmarshalUint64Safe(b); err != nil { return err }
	p.Len, b, err = unmarshalUint32Safe(b);
	return err
}


type sshFXPDataPacket struct {
	sshFXPPacket
	ID   uint32
	Data string
}

func (p sshFXPDataPacket) MarshalBinary() ([]byte, error) {
	b := makePacketHeader(SSH_FXP_DATA, p.ID, p.Data)
	b = marshalUint32(b, p.ID)
	return marshalString(b, p.Data), nil
}

func (p *sshFXPDataPacket) UnmarshalBinary(b []byte) error {
	var err error
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil { return err }
	p.Data, b, err = unmarshalStringSafe(b)
	return err
}


type sshFXPWritePacket struct {
	sshFXPPacket
	ID     uint32
	Handle string
	Offset uint64
	Len    uint32
}

func (p sshFXPWritePacket) MarshalBinary() ([]byte, error) {
	b := makePacketHeader(SSH_FXP_WRITE, p.ID, p.Handle)
	b = marshalUint32(b, p.ID)
	b = marshalString(b, p.Handle)
	b = marshalUint64(b, p.Offset)
	return marshalUint32(b, p.Len), nil
}

func (p *sshFXPWritePacket) UnmarshalBinary(b []byte) error {
	var err error
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil { return err }
	if p.Handle, b, err = unmarshalStringSafe(b); err != nil { return err }
	if p.Offset, b, err = unmarshalUint64Safe(b); err != nil { return err }
	p.Len, b, err = unmarshalUint32Safe(b);
	return err
}


type sshFXPRemovePacket struct {
	sshFXPPacket
	ID       uint32
	Filename string
}

func (p sshFXPRemovePacket) MarshalBinary() ([]byte, error) {
	b := makePacketHeader(SSH_FXP_REMOVE, p.ID, p.Filename)
	b = marshalUint32(b, p.ID)
	return marshalString(b, p.Filename), nil
}

func (p *sshFXPRemovePacket) UnmarshalBinary(b []byte) error {
	var err error
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil { return err }
	p.Filename, b, err = unmarshalStringSafe(b);
	return err
}


type sshFXPRenamePacket struct {
	sshFXPPacket
	ID      uint32
	OldPath string
	NewPath string
}

func (p sshFXPRenamePacket) MarshalBinary() ([]byte, error) {
	b := makePacketHeader(SSH_FXP_RENAME, p.ID, p.OldPath, p.NewPath)
	b = marshalUint32(b, p.ID)
	b = marshalString(b, p.OldPath)
	return marshalString(b, p.NewPath), nil
}

func (p *sshFXPRenamePacket) UnmarshalBinary(b []byte) error {
	var err error
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil { return err }
	if p.OldPath, b, err = unmarshalStringSafe(b); err != nil { return err }
	p.NewPath, b, err = unmarshalStringSafe(b)
	return err
}

type sshFXPMkDirPacket struct {
	sshFXPPacket
	ID    uint32
	Path  string
	Attrs fileAttributes
}

func (p sshFXPMkDirPacket) MarshalBinary() ([]byte, error) {
	b := makePacketHeader(SSH_FXP_MKDIR, p.ID, p.Path, p.Attrs)
	b = marshalUint32(b, p.ID)
	b = marshalString(b, p.Path)
	return marshalFileAttributes(b, p.Attrs), nil
}

func (p *sshFXPMkDirPacket) UnmarshalBinary(b []byte) error {
	var err error
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil { return err }
	if p.Path, b, err = unmarshalStringSafe(b); err != nil { return err }
	p.Attrs, b, err = unmarshalFileAttributesSafe(b)
	return err
}


type sshFXPOpenDirPacket struct {
	sshFXPPacket
	ID   uint32
	Path string
}

func (p sshFXPOpenDirPacket) MarshalBinary() ([]byte, error) {
	b := makePacketHeader(SSH_FXP_OPENDIR, p.ID, p.Path)
	b = marshalUint32(b, p.ID)
	return marshalString(b, p.Path), nil
}

func (p *sshFXPOpenDirPacket) UnmarshalBinary(b []byte) error {
	var err error
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil { return err }
	p.Path, b, err = unmarshalStringSafe(b);
	return err
}


type sshFXPReadDirPacket struct {
	sshFXPPacket
	ID     uint32
	Handle string
}

func (p sshFXPReadDirPacket) MarshalBinary() ([]byte, error) {
	b := makePacketHeader(SSH_FXP_READDIR, p.ID, p.Handle)
	b = marshalUint32(b, p.ID)
	return marshalString(b, p.Handle), nil
}

func (p *sshFXPReadDirPacket) UnmarshalBinary(b []byte) error {
	var err error
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil { return err }
	p.Handle, b, err = unmarshalStringSafe(b)
	return err
}


type namedFile struct {
	Filename string
	Longname string
	Attrs    fileAttributes
}
type sshFXPNamePacket struct {
	sshFXPPacket
	ID    uint32
	Count uint32
	NamedFiles []namedFile
}

func (p sshFXPNamePacket) MarshalBinary() ([]byte, error) {
	b := makePacketHeader(SSH_FXP_NAME, p.ID, p.Count, p.NamedFiles)
	b = marshalUint32(b, p.ID)
	b = marshalUint32(b, p.Count)
	return marshalNamedFiles(b, p.NamedFiles), nil
}

func (p *sshFXPNamePacket) UnmarshalBinary(b []byte) error {
	var err error
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil { return err }
	if p.Count, b, err = unmarshalUint32Safe(b); err != nil { return err }
	p.NamedFiles, b, err = unmarshalNamedFilesSafe(b, p.Count)
	return err
}


type sshFXPStatPacket struct {
	sshFXPPacket
	ID   uint32
	Path string
}

func (p sshFXPStatPacket) MarshalBinary() ([]byte, error) {
	b := makePacketHeader(SSH_FXP_STAT, p.ID, p.Path)
	b = marshalUint32(b, p.ID)
	return marshalString(b, p.Path), nil
}

func (p *sshFXPStatPacket) UnmarshalBinary(b []byte) error {
	var err error
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil { return err }
	p.Path, b, err = unmarshalStringSafe(b)
	return err
}


type sshFXPLStatPacket struct {
	sshFXPPacket
	ID   uint32
	Path string
}

func (p sshFXPLStatPacket) MarshalBinary() ([]byte, error) {
	b := makePacketHeader(SSH_FXP_LSTAT, p.ID, p.Path)
	b = marshalUint32(b, p.ID)
	return marshalString(b, p.Path), nil
}

func (p *sshFXPLStatPacket) UnmarshalBinary(b []byte) error {
	var err error
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil { return err }
	p.Path, b, err = unmarshalStringSafe(b)
	return err
}


type sshFXPAttrsPacket struct {
	sshFXPPacket
	ID    uint32
	Attrs fileAttributes
}

func (p sshFXPAttrsPacket) MarshalBinary() ([]byte, error) {
	b := makePacketHeader(SSH_FXP_ATTRS, p.ID, p.Attrs)
	b = marshalUint32(b, p.ID)
	return marshalFileAttributes(b, p.Attrs), nil
}

func (p *sshFXPAttrsPacket) UnmarshalBinary(b []byte) error {
	var err error
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil { return err }
	p.Attrs, b, err = unmarshalFileAttributesSafe(b)
	return err
}


type sshFXPFStatPacket struct {
	sshFXPPacket
	ID     uint32
	Handle string
}

func (p sshFXPFStatPacket) MarshalBinary() ([]byte, error) {
	b := makePacketHeader(SSH_FXP_FSTAT, p.ID, p.Handle)
	b = marshalUint32(b, p.ID)
	return marshalString(b, p.Handle), nil
}

func (p *sshFXPFStatPacket) UnmarshalBinary(b []byte) error {
	var err error
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil { return err }
	p.Handle, b, err = unmarshalStringSafe(b)
	return err
}


type sshFXPSetStatPacket struct {
	sshFXPPacket
	ID    uint32
	Path  string
	Attrs fileAttributes
}

func (p sshFXPSetStatPacket) MarshalBinary() ([]byte, error) {
	b := makePacketHeader(SSH_FXP_SETSTAT, p.ID, p.Path, p.Attrs)
	b = marshalUint32(b, p.ID)
	b = marshalString(b, p.Path)
	return marshalFileAttributes(b, p.Attrs), nil
}

func (p *sshFXPSetStatPacket) UnmarshalBinary(b []byte) error {
	var err error
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil { return err }
	if p.Path, b, err = unmarshalStringSafe(b); err != nil { return err }
	p.Attrs, b, err = unmarshalFileAttributesSafe(b)
	return err
}


type sshFXPFSetStatPacket struct {
	sshFXPPacket
	ID      uint32
	Handle  string
	Attrs   fileAttributes
}

func (p sshFXPFSetStatPacket) MarshalBinary() ([]byte, error) {
	b := makePacketHeader(SSH_FXP_FSETSTAT, p.ID, p.Handle, p.Attrs)
	b = marshalUint32(b, p.ID)
	b = marshalString(b, p.Handle)
	return marshalFileAttributes(b, p.Attrs), nil
}

func (p *sshFXPFSetStatPacket) UnmarshalBinary(b []byte) error {
	var err error
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil { return err }
	if p.Handle, b, err = unmarshalStringSafe(b); err != nil { return err }
	p.Attrs, b, err = unmarshalFileAttributesSafe(b)
	return err
}


type sshFXPReadLinkPacket struct {
	sshFXPPacket
	ID   uint32
	Path string
}

func (p sshFXPReadLinkPacket) MarshalBinary() ([]byte, error) {
	b := makePacketHeader(SSH_FXP_READLINK, p.ID, p.Path)
	b = marshalUint32(b, p.ID)
	return marshalString(b, p.Path), nil
}

func (p *sshFXPReadLinkPacket) UnmarshalBinary(b []byte) error {
	var err error
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil { return err }
	p.Path, b, err = unmarshalStringSafe(b)
	return err
}


type sshFXPSymlinkPacket struct {
	sshFXPPacket
	ID         uint32
	LinkPath   string
	TargetPath string
}

func (p sshFXPSymlinkPacket) MarshalBinary() ([]byte, error) {
	b := makePacketHeader(SSH_FXP_SYMLINK, p.ID, p.LinkPath, p.TargetPath)
	b = marshalUint32(b, p.ID)
	b = marshalString(b, p.LinkPath)
	return marshalString(b, p.TargetPath), nil
}

func (p *sshFXPSymlinkPacket) UnmarshalBinary(b []byte) error {
	var err error
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil { return err }
	if p.LinkPath, b, err = unmarshalStringSafe(b); err != nil { return err }
	p.TargetPath, b, err = unmarshalStringSafe(b)
	return err
}


type sshFXPRealPathPacket struct {
	sshFXPPacket
	ID   uint32
	Path string
}

func (p sshFXPRealPathPacket) MarshalBinary() ([]byte, error) {
	b := makePacketHeader(SSH_FXP_REALPATH, p.ID, p.Path)
	b = marshalUint32(b, p.ID)
	return marshalString(b, p.Path), nil
}

func (p *sshFXPRealPathPacket) UnmarshalBinary(b []byte) error {
	var err error
	if p.ID, b, err = unmarshalUint32Safe(b); err != nil { return err }
	p.Path, b, err = unmarshalStringSafe(b)
	return err
}