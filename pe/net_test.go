package pe

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestParseNetMetadataNames(t *testing.T) {
	strings := []byte("\x00Hello\x00App\x00")
	typeDef := make([]byte, 14)
	binary.LittleEndian.PutUint16(typeDef[4:], 1) // "Hello"

	assembly := make([]byte, 22)
	binary.LittleEndian.PutUint16(assembly[18:], 7) // "App"

	tables := make([]byte, 24+8)
	binary.LittleEndian.PutUint64(tables[8:], (1<<2)|(1<<32))
	binary.LittleEndian.PutUint32(tables[24:], 1)
	binary.LittleEndian.PutUint32(tables[28:], 1)
	tables = append(tables, typeDef...)
	tables = append(tables, assembly...)

	ver := []byte("v4.0.30319\x00\x00")
	md, assemblyName, types, err := parseNetMetadata(buildMeta(ver, []stream{
		{name: "#Strings", body: strings},
		{name: "#~", body: tables},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if string(bytes.TrimRight(md.VersionString, "\x00")) != "v4.0.30319" {
		t.Fatalf("version %q", md.VersionString)
	}
	if assemblyName != "App" || len(types) != 1 || types[0] != "Hello" {
		t.Fatalf("assembly %q types %v", assemblyName, types)
	}
}

func TestParseNetMetadataRejectsHugeStreamCount(t *testing.T) {
	var meta bytes.Buffer
	meta.Write([]byte{'B', 'S', 'J', 'B'})
	meta.Write(make([]byte, 8))
	var u32 [4]byte
	binary.LittleEndian.PutUint32(u32[:], 4)
	meta.Write(u32[:])
	meta.Write([]byte{0, 0, 0, 0})
	meta.Write([]byte{0, 0})
	var u16 [2]byte
	binary.LittleEndian.PutUint16(u16[:], uint16(maxCLRStreams+1))
	meta.Write(u16[:])
	if _, _, _, err := parseNetMetadata(meta.Bytes()); err == nil {
		t.Fatal("huge stream count was accepted")
	}
}

type stream struct {
	name string
	body []byte
}

func buildMeta(ver []byte, streams []stream) []byte {
	var header bytes.Buffer
	header.Write([]byte{'B', 'S', 'J', 'B'})
	var u16 [2]byte
	binary.LittleEndian.PutUint16(u16[:], 1)
	header.Write(u16[:])
	header.Write(u16[:])
	header.Write(make([]byte, 4))
	var u32 [4]byte
	binary.LittleEndian.PutUint32(u32[:], uint32(len(ver)))
	header.Write(u32[:])
	header.Write(ver)
	header.Write(make([]byte, 2))
	binary.LittleEndian.PutUint16(u16[:], uint16(len(streams)))
	header.Write(u16[:])
	bodies := header.Len()
	for _, s := range streams {
		bodies += 8 + align4(len(s.name)+1)
	}
	var out bytes.Buffer
	out.Write(header.Bytes())
	off := bodies
	for _, s := range streams {
		binary.LittleEndian.PutUint32(u32[:], uint32(off))
		out.Write(u32[:])
		binary.LittleEndian.PutUint32(u32[:], uint32(len(s.body)))
		out.Write(u32[:])
		out.WriteString(s.name)
		out.WriteByte(0)
		for out.Len()%4 != 0 {
			out.WriteByte(0)
		}
		off += len(s.body)
	}
	for _, s := range streams {
		out.Write(s.body)
	}
	return out.Bytes()
}

func align4(n int) int { return (n + 3) &^ 3 }
