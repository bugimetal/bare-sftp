package bsftp

const (
	SSH_FILEXFER_ATTR_SIZE        = 0x00000001
    SSH_FILEXFER_ATTR_UIDGID      = 0x00000002
    SSH_FILEXFER_ATTR_PERMISSIONS = 0x00000004
    SSH_FILEXFER_ATTR_ACMODTIME   = 0x00000008
    // SSH_FILEXFER_ATTR_EXTENDED    = 0x80000000
)

type fileAttributes struct {
	Flags uint32
	Stat  attrs
}

/*
	The `size' field specifies the size of the file in bytes.

	The `uid' and `gid' fields contain numeric Unix-like user and group
	identifiers, respectively.

	The `permissions' field contains a bit mask of file permissions as
	defined by posix [1].

	The `atime' and `mtime' contain the access and modification times of
	the files, respectively.  They are represented as seconds from Jan 1,
	1970 in UTC.
*/

type attrs struct {
	Size        uint64
	UID         uint32
	GID         uint32
	Permissions uint32
	ATime       uint32
	MTime       uint32
}

func marshalFileAttributes(b []byte, v fileAttributes) []byte {
	b = marshalUint32(b, v.Flags)

	if v.Flags&SSH_FILEXFER_ATTR_SIZE == SSH_FILEXFER_ATTR_SIZE {
		b = marshalUint64(b, v.Stat.Size)
	}

	if v.Flags&SSH_FILEXFER_ATTR_UIDGID == SSH_FILEXFER_ATTR_UIDGID {
		b = marshalUint32(b, v.Stat.UID)
		b = marshalUint32(b, v.Stat.GID)
	}

	if v.Flags&SSH_FILEXFER_ATTR_PERMISSIONS == SSH_FILEXFER_ATTR_PERMISSIONS {
		b = marshalUint32(b, v.Stat.Permissions)
	}

	if v.Flags&SSH_FILEXFER_ATTR_ACMODTIME == SSH_FILEXFER_ATTR_ACMODTIME {
		b = marshalUint32(b, v.Stat.ATime)
		b = marshalUint32(b, v.Stat.MTime)
	}

	return b
}

func unmarshalFileAttributesSafe(b []byte) (fileAttributes, []byte, error) {
	var err error
	fAttrs := fileAttributes{}
	if fAttrs.Flags, b, err = unmarshalUint32Safe(b); err != nil { return fAttrs, nil, err }
	fAttrs.Stat = attrs{}

	if fAttrs.Flags&SSH_FILEXFER_ATTR_SIZE == SSH_FILEXFER_ATTR_SIZE {
		if fAttrs.Stat.Size, b, err = unmarshalUint64Safe(b); err != nil { return fAttrs, nil, err }
	}

	if fAttrs.Flags&SSH_FILEXFER_ATTR_UIDGID == SSH_FILEXFER_ATTR_UIDGID {
		if fAttrs.Stat.UID, b, err = unmarshalUint32Safe(b); err != nil { return fAttrs, nil, err }
		if fAttrs.Stat.GID, b, err = unmarshalUint32Safe(b); err != nil { return fAttrs, nil, err }
	}

	if fAttrs.Flags&SSH_FILEXFER_ATTR_PERMISSIONS == SSH_FILEXFER_ATTR_PERMISSIONS {
		if fAttrs.Stat.Permissions, b, err = unmarshalUint32Safe(b); err != nil { return fAttrs, nil, err }
	}

	if fAttrs.Flags&SSH_FILEXFER_ATTR_ACMODTIME == SSH_FILEXFER_ATTR_ACMODTIME {
		if fAttrs.Stat.ATime, b, err = unmarshalUint32Safe(b); err != nil { return fAttrs, nil, err }
		if fAttrs.Stat.MTime, b, err = unmarshalUint32Safe(b); err != nil { return fAttrs, nil, err }
	}

	return fAttrs, b, err
}