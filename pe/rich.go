package pe

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// RichEntry is one decoded Microsoft Rich header record.
// ToolID is the product id. Version is the build number. Count is how many times that tool ran.
type RichEntry struct {
	ToolID  uint16
	Version uint16
	Count   uint32
}

// RichEntries XOR-decodes the Rich header already stored on the file.
// A header larger than 1 MiB, or more than 256 entries, is rejected.
func (f *File) RichEntries() ([]RichEntry, error) {
	raw := f.RichHeader
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) > 1<<20 {
		return nil, fmt.Errorf("rich header is %d bytes", len(raw))
	}
	rich := bytes.LastIndex(raw, []byte("Rich"))
	if rich < 8 || rich+8 > len(raw) || rich%4 != 0 {
		return nil, nil
	}
	key := binary.LittleEndian.Uint32(raw[rich+4 : rich+8])
	buf := append([]byte(nil), raw[:rich]...)
	for i := 0; i+4 <= len(buf); i += 4 {
		v := binary.LittleEndian.Uint32(buf[i:]) ^ key
		binary.LittleEndian.PutUint32(buf[i:], v)
	}
	dans := bytes.Index(buf, []byte("DanS"))
	if dans < 0 || (dans%4) != 0 {
		return nil, fmt.Errorf("rich header missing DanS")
	}
	rest := buf[dans+4:]
	for len(rest) >= 4 && binary.LittleEndian.Uint32(rest[:4]) == 0 {
		rest = rest[4:]
	}
	if len(rest)%8 != 0 {
		return nil, fmt.Errorf("rich header truncated")
	}
	n := len(rest) / 8
	if n > 256 {
		return nil, fmt.Errorf("rich header has %d entries", n)
	}
	out := make([]RichEntry, 0, n)
	for len(rest) >= 8 {
		comp := binary.LittleEndian.Uint32(rest[:4])
		count := binary.LittleEndian.Uint32(rest[4:8])
		out = append(out, RichEntry{
			ToolID:  uint16(comp >> 16),
			Version: uint16(comp),
			Count:   count,
		})
		rest = rest[8:]
	}
	return out, nil
}
