package bsftp

const (
	UINT8_COST = 1
	UINT32_COST = 4
	UINT64_COST = 8
)

func calculatePacketSize(data ...interface{}) uint32 {
	var size uint32 = 0

	for _, v := range data {
		switch v.(type) {
			case byte: size += UINT8_COST
			case uint32: size += UINT32_COST
			case int32: size += UINT32_COST
			case string: size += uint32(UINT32_COST + len(v.(string)))
			case []extensionPair:
				for _, ext := range v.([]extensionPair) {
					size += uint32(UINT32_COST + len(ext.ExtensionName))
					size += uint32(UINT32_COST + len(ext.ExtensionData))
				}
			case fileAttributes:
				size += UINT32_COST
				fAttrs := v.(fileAttributes)
				
				if fAttrs.Flags&SSH_FILEXFER_ATTR_SIZE == SSH_FILEXFER_ATTR_SIZE {
					size += UINT64_COST
				}
			
				if fAttrs.Flags&SSH_FILEXFER_ATTR_UIDGID == SSH_FILEXFER_ATTR_UIDGID {
					size += UINT32_COST * 2
				}
			
				if fAttrs.Flags&SSH_FILEXFER_ATTR_PERMISSIONS == SSH_FILEXFER_ATTR_PERMISSIONS {
					size += UINT64_COST
				}
			
				if fAttrs.Flags&SSH_FILEXFER_ATTR_ACMODTIME == SSH_FILEXFER_ATTR_ACMODTIME {
					size += UINT32_COST * 2
				}
			case uint64: size += UINT64_COST
			case int64: size += UINT64_COST
			case []namedFile:
				for _, file := range v.([]namedFile) {
					size += uint32(UINT32_COST + len(file.Filename))
					size += uint32(UINT32_COST + len(file.Longname))
					size += calculatePacketSize(file.Attrs)
				}
		}
	}

	return size
}

func makePacketHeader(tahyp byte, data ...interface{}) []byte {
	length := UINT8_COST + calculatePacketSize(data) // to prevent unnecessary array allocation, manually add type field length
	b := make([]byte, 0, length + UINT32_COST) // the length fields of bidirectional packets do not account for themselves
	b = marshalUint32(b, length)
	return marshalByte(b, tahyp)
}

// convert all unmarshal functions to use exploitative memory overflow casting?
// return *(*int32)(unsafe.Pointer(&b[0]))

func marshalUint32(b []byte, v uint32) []byte {
	return append(b, byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v))
}

func unmarshalUint32(b []byte) (uint32, []byte) {
	v := uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
	return v, b[4:]
}

func unmarshalUint32Safe(b []byte) (uint32, []byte, error) {
	if len(b) < 4 {
		return 0, nil, shortPacketError
	}
	
	v, b := unmarshalUint32(b)
	return v, b, nil
}

func marshalString(b []byte, v string) []byte {
	return append(marshalUint32(b, uint32(len(v))), v...)
}

func unmarshalStringSafe(b []byte) (string, []byte, error) {
	n, b, err := unmarshalUint32Safe(b)
	if err != nil {
		return "", nil, err
	}

	if int64(n) > int64(len(b)) {
		return "", nil, shortPacketError
	}

	return string(b[:n]), b[n:], nil
}

func marshalExtensions(b []byte, v []extensionPair) []byte {
	for _, ext := range v {
		b = marshalString(b, ext.ExtensionName)
		b = marshalString(b, ext.ExtensionData)
	}

	return b
}

func marshalByte(b []byte, v byte) []byte {
	return append(b, v)
}

func unmarshalByte(b []byte) (byte, []byte) {
	return b[0], b[1:]
}

func unmarshalByteSafe(b []byte) (byte, []byte, error) {
	if len(b) < 1 {
		return 0, nil, shortPacketError
	}

	v, b := unmarshalByte(b)
	return v, b, nil
}

func marshalUint64(b []byte, v uint64) []byte {
	return marshalUint32(marshalUint32(b, uint32(v >> 32)), uint32(v))
}

func unmarshalUint64(b []byte) (uint64, []byte) {
	h, b := unmarshalUint32(b)
	l, b := unmarshalUint32(b)
	return uint64(h)<<32 | uint64(l), b
}

func unmarshalUint64Safe(b []byte) (uint64, []byte, error) {
	if len(b) < 8 {
		return 0, nil, shortPacketError
	}

	v, b := unmarshalUint64(b)
	return v, b, nil
}

func marshalInt64(b []byte, v int64) []byte {
	return marshalUint64(b, uint64(v))
}

func unmarshalInt64(b []byte) (int64, []byte) {
	v, b := unmarshalUint64(b)
	return int64(v), b
}

func unmarshalInt64Safe(b []byte) (int64, []byte, error) {
	v, b, e := unmarshalUint64Safe(b)
	return int64(v), b, e
}

func marshalNamedFiles(b []byte, v []namedFile) []byte {
	for _, ext := range v {
		b = marshalString(b, ext.Filename)
		b = marshalString(b, ext.Longname)
		b = marshalFileAttributes(b, ext.Attrs)
	}

	return b
}

func unmarshalNamedFilesSafe(b []byte, count uint32) ([]namedFile, []byte, error) {
	files := make([]namedFile, 0, count)

	for i := 0; uint32(i) < count; i++ {
		filename, b, err := unmarshalStringSafe(b)
		if err != nil {
			return nil, nil, err
		}

		longname, b, err := unmarshalStringSafe(b)
		if err != nil {
			return nil, nil, err
		}

		attrs, b, err := unmarshalFileAttributesSafe(b)
		if err != nil {
			return nil, nil, err
		}

		files[i] = namedFile{
			Filename: filename,
			Longname: longname,
			Attrs: attrs,
		}
	}

	return files, b, nil
}