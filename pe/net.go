package pe

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	maxCLRDirectory = 1024
	maxCLRMetadata  = 4 << 20
	maxCLRVersion   = 256
	maxCLRStreams   = 16
	maxCLRTypes     = 64
	maxCLRRows      = 1 << 20
)

type IMAGE_COR20_HEADER struct {
	Cb                          uint32
	MajorRuntimeVersion         uint16
	MinorRuntimeVersion         uint16
	MetaDataRVA                 uint32
	MetaDataSize                uint32
	Flags                       uint32
	EntryPointToken             uint32
	ResourcesRVA                uint32
	ResourcesSize               uint32
	StrongNameSignatureRVA      uint32
	StrongNameSignatureSize     uint32
	CodeManagerTableRVA         uint32
	CodeManagerTableSize        uint32
	VTableFixupsRVA             uint32
	VTableFixupsSize            uint32
	ExportAddressTableJumpsRVA  uint32
	ExportAddressTableJumpsSize uint32
	ManagedNativeHeaderRVA      uint32
	ManagedNativeHeaderSize     uint32
}

// Net provides a public interface for getting at some net info.
type Net struct {
	NetDirectory IMAGE_COR20_HEADER
	MetaData     NetMetaData
	Assembly     string
	Types        []string
	Error        string
}

type NetMetaData struct {
	Signature       [4]byte // should be BSJB
	MajorVersion    uint16
	MinorVersion    uint16
	Reserved        uint32
	VersionLength   uint32
	VersionString   []byte
	Flags           uint16
	NumberOfStreams uint16
}

// NetCLRVersion returns the CLR version specified by the binary.
// An empty string means the version was not read. Trailing nulls are stripped.
func (f File) NetCLRVersion() string {
	b := f.Net.MetaData.VersionString
	for i, x := range b {
		if x == 0x00 {
			b = b[:i]
			break
		}
	}
	return string(b)
}

func (f *File) readNet(r io.ReaderAt, memoryMode bool) error {
	var va, size uint32
	switch v := f.OptionalHeader.(type) {
	case *OptionalHeader32:
		va = v.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress
		size = v.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size
	case *OptionalHeader64:
		va = v.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress
		size = v.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size
	default:
		return fmt.Errorf("optional header missing")
	}
	dir, err := readBounded(r, f.clrOffset(va, memoryMode), size, maxCLRDirectory)
	if err != nil {
		return fmt.Errorf("clr directory: %w", err)
	}
	if len(dir) < 72 {
		return fmt.Errorf("clr directory is %d bytes", len(dir))
	}
	if err := binary.Read(newSliceReader(dir[:72]), binary.LittleEndian, &f.Net.NetDirectory); err != nil {
		return err
	}
	meta, err := readBounded(r, f.clrOffset(f.Net.NetDirectory.MetaDataRVA, memoryMode), f.Net.NetDirectory.MetaDataSize, maxCLRMetadata)
	if err != nil {
		return fmt.Errorf("clr metadata: %w", err)
	}
	md, assembly, types, err := parseNetMetadata(meta)
	f.Net.MetaData = md
	f.Net.Assembly = assembly
	f.Net.Types = types
	return err
}

func (f *File) clrOffset(rva uint32, memoryMode bool) int64 {
	if memoryMode {
		return int64(rva)
	}
	return int64(f.RVAToFileOffset(rva))
}

func readBounded(r io.ReaderAt, off int64, size, cap uint32) ([]byte, error) {
	if size == 0 || size > cap || off < 0 {
		return nil, fmt.Errorf("size %d at offset %d", size, off)
	}
	buf := make([]byte, size)
	n, err := r.ReadAt(buf, off)
	if n < len(buf) {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return buf, nil
}

type sliceReader struct {
	b []byte
	i int
}

func newSliceReader(b []byte) *sliceReader { return &sliceReader{b: b} }

func (r *sliceReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}

func parseNetMetadata(buf []byte) (NetMetaData, string, []string, error) {
	var md NetMetaData
	if len(buf) < 20 {
		return md, "", nil, fmt.Errorf("metadata is %d bytes", len(buf))
	}
	r := newSliceReader(buf)
	if err := binary.Read(r, binary.LittleEndian, &md.Signature); err != nil {
		return md, "", nil, err
	}
	if md.Signature != [4]byte{'B', 'S', 'J', 'B'} {
		return md, "", nil, fmt.Errorf("metadata signature %q", md.Signature)
	}
	if err := binary.Read(r, binary.LittleEndian, &md.MajorVersion); err != nil {
		return md, "", nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &md.MinorVersion); err != nil {
		return md, "", nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &md.Reserved); err != nil {
		return md, "", nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &md.VersionLength); err != nil {
		return md, "", nil, err
	}
	if md.VersionLength == 0 || md.VersionLength > maxCLRVersion || int(md.VersionLength) > len(buf)-r.i {
		return md, "", nil, fmt.Errorf("metadata version length %d", md.VersionLength)
	}
	md.VersionString = make([]byte, md.VersionLength)
	if _, err := io.ReadFull(r, md.VersionString); err != nil {
		return md, "", nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &md.Flags); err != nil {
		return md, "", nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &md.NumberOfStreams); err != nil {
		return md, "", nil, err
	}
	if md.NumberOfStreams == 0 || md.NumberOfStreams > maxCLRStreams {
		return md, "", nil, fmt.Errorf("metadata stream count %d", md.NumberOfStreams)
	}
	var strings, tables []byte
	for i := 0; i < int(md.NumberOfStreams); i++ {
		var off, size uint32
		if err := binary.Read(r, binary.LittleEndian, &off); err != nil {
			return md, "", nil, err
		}
		if err := binary.Read(r, binary.LittleEndian, &size); err != nil {
			return md, "", nil, err
		}
		name, err := readStreamName(r)
		if err != nil {
			return md, "", nil, err
		}
		if size > maxCLRMetadata || off > uint32(len(buf)) || size > uint32(len(buf))-off {
			return md, "", nil, fmt.Errorf("metadata stream %q is %d bytes at %d", name, size, off)
		}
		body := buf[off : off+size]
		switch name {
		case "#Strings":
			strings = body
		case "#~", "#-":
			tables = body
		}
	}
	if tables == nil {
		return md, "", nil, fmt.Errorf("metadata has no table stream")
	}
	assembly, types, err := readNetTables(tables, strings)
	return md, assembly, types, err
}

func readStreamName(r *sliceReader) (string, error) {
	start := r.i
	for n := 0; n < 32; n++ {
		if r.i >= len(r.b) {
			return "", io.ErrUnexpectedEOF
		}
		if r.b[r.i] == 0 {
			name := string(r.b[start:r.i])
			r.i++
			for r.i%4 != 0 {
				if r.i >= len(r.b) {
					return "", io.ErrUnexpectedEOF
				}
				r.i++
			}
			return name, nil
		}
		r.i++
	}
	return "", fmt.Errorf("metadata stream name is too long")
}

func readNetTables(tables, strings []byte) (string, []string, error) {
	if len(tables) < 24 {
		return "", nil, fmt.Errorf("table stream is %d bytes", len(tables))
	}
	heapSizes := tables[6]
	valid := binary.LittleEndian.Uint64(tables[8:])
	pos := 24
	var rows [64]uint32
	for bit := 0; bit < 64; bit++ {
		if valid&(1<<uint(bit)) == 0 {
			continue
		}
		if pos+4 > len(tables) {
			return "", nil, io.ErrUnexpectedEOF
		}
		rows[bit] = binary.LittleEndian.Uint32(tables[pos:])
		if rows[bit] > maxCLRRows {
			return "", nil, fmt.Errorf("metadata table %d has %d rows", bit, rows[bit])
		}
		pos += 4
	}
	strW := indexWidth(heapSizes&0x1 != 0)
	guidW := indexWidth(heapSizes&0x2 != 0)
	blobW := indexWidth(heapSizes&0x4 != 0)
	var assembly string
	var types []string
	for bit := 0; bit < 64; bit++ {
		if bit > 32 {
			break
		}
		if valid&(1<<uint(bit)) == 0 {
			continue
		}
		width, ok := metadataRowWidth(bit, rows, strW, guidW, blobW)
		if !ok {
			return "", nil, fmt.Errorf("metadata table %d is not supported", bit)
		}
		need := uint64(rows[bit]) * uint64(width)
		if need > uint64(len(tables)-pos) {
			return "", nil, fmt.Errorf("metadata table %d does not fit", bit)
		}
		body := tables[pos : pos+int(need)]
		pos += int(need)
		switch bit {
		case 2: // TypeDef
			types = typeNames(body, rows[bit], width, strW, strings)
		case 32: // Assembly
			assembly = assemblyName(body, width, strW, blobW, strings)
		}
	}
	return assembly, types, nil
}

func indexWidth(wide bool) int {
	if wide {
		return 4
	}
	return 2
}

func simpleIndex(rows uint32) int {
	if rows >= 65536 {
		return 4
	}
	return 2
}

func codedIndex(tagBits int, rows [64]uint32, tables ...int) int {
	var max uint32
	for _, t := range tables {
		if t >= 0 && t < len(rows) && rows[t] > max {
			max = rows[t]
		}
	}
	if max >= 1<<uint(16-tagBits) {
		return 4
	}
	return 2
}

func metadataRowWidth(table int, rows [64]uint32, strW, guidW, blobW int) (int, bool) {
	tdr := codedIndex(2, rows, 2, 1, 27)
	res := codedIndex(2, rows, 0, 26, 35, 1)
	hasConst := codedIndex(2, rows, 4, 8, 23)
	hasCA := codedIndex(5, rows, 6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43)
	caType := codedIndex(3, rows, 6, 10)
	hasFM := codedIndex(1, rows, 4, 8)
	hasDS := codedIndex(2, rows, 2, 6, 32)
	mrp := codedIndex(3, rows, 2, 1, 26, 6, 27)
	hasSem := codedIndex(1, rows, 20, 23)
	mdr := codedIndex(1, rows, 6, 10)
	mfwd := codedIndex(1, rows, 4, 6)
	fieldI := simpleIndex(rows[4])
	methodI := simpleIndex(rows[6])
	paramI := simpleIndex(rows[8])
	eventI := simpleIndex(rows[20])
	propI := simpleIndex(rows[23])
	typeI := simpleIndex(rows[2])
	switch table {
	case 0:
		return 2 + strW + guidW*3, true
	case 1:
		return res + strW + strW, true
	case 2:
		return 4 + strW + strW + tdr + fieldI + methodI, true
	case 3:
		return fieldI, true
	case 4:
		return 2 + strW + blobW, true
	case 5:
		return methodI, true
	case 6:
		return 4 + 2 + 2 + strW + blobW + paramI, true
	case 7:
		return paramI, true
	case 8:
		return 2 + 2 + strW, true
	case 9:
		return typeI + tdr, true
	case 10:
		return mrp + strW + blobW, true
	case 11:
		return 1 + 1 + hasConst + blobW, true
	case 12:
		return hasCA + caType + blobW, true
	case 13:
		return hasFM + blobW, true
	case 14:
		return 2 + hasDS + blobW, true
	case 15:
		return 2 + 4 + typeI, true
	case 16:
		return 4 + fieldI, true
	case 17:
		return blobW, true
	case 18:
		return typeI + eventI, true
	case 19:
		return eventI, true
	case 20:
		return 2 + strW + tdr, true
	case 21:
		return typeI + propI, true
	case 22:
		return propI, true
	case 23:
		return 2 + strW + blobW, true
	case 24:
		return 2 + methodI + hasSem, true
	case 25:
		return typeI + mdr + mdr, true
	case 26:
		return strW, true
	case 27:
		return blobW, true
	case 28:
		return 2 + mfwd + strW + simpleIndex(rows[26]), true
	case 29:
		return 4 + fieldI, true
	case 30, 31:
		return 8, true
	case 32:
		return 4 + 2 + 2 + 2 + 2 + 4 + blobW + strW + strW, true
	default:
		return 0, false
	}
}

func assemblyName(body []byte, width, strW, blobW int, strings []byte) string {
	// HashAlgId(4) Major Minor Build Revision (8) Flags(4) PublicKey Name Culture
	off := 4 + 8 + 4 + blobW
	if off+strW > width || off+strW > len(body) {
		return ""
	}
	return heapString(strings, readIndex(body[off:], strW))
}

func typeNames(body []byte, count uint32, width, strW int, strings []byte) []string {
	n := int(count)
	if n > maxCLRTypes {
		n = maxCLRTypes
	}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		row := body[i*width : (i+1)*width]
		if 4+strW+strW > len(row) {
			break
		}
		name := heapString(strings, readIndex(row[4:], strW))
		ns := heapString(strings, readIndex(row[4+strW:], strW))
		if ns != "" && name != "" {
			name = ns + "." + name
		}
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

func readIndex(b []byte, width int) uint32 {
	if width == 4 {
		if len(b) < 4 {
			return 0
		}
		return binary.LittleEndian.Uint32(b)
	}
	if len(b) < 2 {
		return 0
	}
	return uint32(binary.LittleEndian.Uint16(b))
}

func heapString(heap []byte, index uint32) string {
	if index == 0 || int(index) >= len(heap) {
		return ""
	}
	end := int(index)
	for end < len(heap) && heap[end] != 0 {
		end++
		if end-int(index) > 1024 {
			break
		}
	}
	return string(heap[index:end])
}
