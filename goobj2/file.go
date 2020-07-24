// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package goobj implements reading of Go object files and archives.
//
// TODO(rsc): Decide where this package should live. (golang.org/issue/6932)
// TODO(rsc): Decide the appropriate integer types for various fields.

package goobj2

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/Binject/debug/goobj2/internal/goobj2"
	"github.com/Binject/debug/goobj2/internal/objabi"
)

// A Package is a parsed Go object file or archive defining a Go package.
type Package struct {
	Header        Header
	ImportPath    string        // import path denoting this package
	Imports       []ImportedPkg // packages imported by this package
	Packages      []string
	DWARFFileList []string        // List of files for the DWARF .debug_lines section
	SymRefs       []SymID         // list of symbol names and versions referred to by this pack
	Syms          []*Sym          // symbols defined by this package
	MaxVersion    int64           // maximum Version in any SymID in Syms
	Arch          string          // architecture
	Native        []*NativeReader // native object data (e.g. ELF)
}

type Header struct {
	Magic       string
	Fingerprint [8]byte
	Flags       uint32
	offsets     [goobj2.NBlk]uint32
}

type ImportedPkg struct {
	Pkg         string
	Fingerprint [8]byte
}

// A Sym is a named symbol in an object file.
type Sym struct {
	SymID                // symbol identifier (name and version)
	Kind  objabi.SymKind // kind of symbol
	DupOK bool           // are duplicate definitions okay?
	Size  int64          // size of corresponding data
	Type  SymID          // symbol for Go type information
	Data  Data           // memory image of symbol
	Reloc []Reloc        // relocations to apply to Data
	Func  *Func          // additional data for functions
}

// A SymID - the combination of Name and Version - uniquely identifies
// a symbol within a package.
type SymID struct {
	// Name is the name of a symbol.
	Name string

	// Version is zero for symbols with global visibility.
	// Symbols with only file visibility (such as file-level static
	// declarations in C) have a non-zero version distinguishing
	// a symbol in one file from a symbol of the same name
	// in another file
	Version int64
}

func (s SymID) String() string {
	if s.Version == 0 {
		return s.Name
	}
	return fmt.Sprintf("%s<%d>", s.Name, s.Version)
}

// A Data is a reference to data stored in an object file.
// It records the offset and size of the data, so that a client can
// read the data only if necessary.
type Data struct {
	Offset int64
	Size   int64
}

// A Reloc describes a relocation applied to a memory image to refer
// to an address within a particular symbol.
type Reloc struct {
	// The bytes at [Offset, Offset+Size) within the containing Sym
	// should be updated to refer to the address Add bytes after the start
	// of the symbol Sym.
	Offset int64
	Size   int64
	Sym    SymID
	Add    int64

	// The Type records the form of address expected in the bytes
	// described by the previous fields: absolute, PC-relative, and so on.
	// TODO(rsc): The interpretation of Type is not exposed by this package.
	Type objabi.RelocType
}

// A Var describes a variable in a function stack frame: a declared
// local variable, an input argument, or an output result.
type Var struct {
	// The combination of Name, Kind, and Offset uniquely
	// identifies a variable in a function stack frame.
	// Using fewer of these - in particular, using only Name - does not.
	Name   string // Name of variable.
	Kind   int64  // TODO(rsc): Define meaning.
	Offset int64  // Frame offset. TODO(rsc): Define meaning.

	Type SymID // Go type for variable.
}

// Func contains additional per-symbol information specific to functions.
type Func struct {
	Args     int64      // size in bytes of argument frame: inputs and outputs
	Frame    int64      // size in bytes of local variable frame
	Align    uint32     // alignment requirement in bytes for the address of the function
	Leaf     bool       // function omits save of link register (ARM)
	NoSplit  bool       // function omits stack split prologue
	TopFrame bool       // function is the top of the call stack
	Var      []Var      // detail about local variables
	PCSP     Data       // PC → SP offset map
	PCFile   Data       // PC → file number map (index into File)
	PCLine   Data       // PC → line number map
	PCInline Data       // PC → inline tree index map
	PCData   []Data     // PC → runtime support data map
	FuncData []FuncData // non-PC-specific runtime support data
	File     []string   // paths indexed by PCFile
	InlTree  []InlinedCall
}

// TODO: Add PCData []byte and PCDataIter (similar to liblink).

// A FuncData is a single function-specific data value.
type FuncData struct {
	Sym    SymID // symbol holding data
	Offset int64 // offset into symbol for funcdata pointer
}

// An InlinedCall is a node in an InlTree.
// See cmd/internal/obj.InlTree for details.
type InlinedCall struct {
	Parent   int64
	File     string
	Line     int64
	Func     SymID
	ParentPC int64
}

type NativeReader struct {
	Name string
	io.ReaderAt
}

var (
	archiveHeader = []byte("!<arch>\n")
	archiveMagic  = []byte("`\n")
	goobjHeader   = []byte("go objec") // truncated to size of archiveHeader

	errCorruptArchive   = errors.New("corrupt archive")
	errTruncatedArchive = errors.New("truncated archive")
	errCorruptObject    = errors.New("corrupt object file")
	errNotObject        = errors.New("unrecognized object file format")
)

// An objReader is an object file reader.
type objReader struct {
	p          *Package
	b          *bufio.Reader
	f          *os.File
	err        error
	offset     int64
	dataOffset int64
	limit      int64
	tmp        [256]byte
	pkgprefix  string
}

// init initializes r to read package p from f.
func (r *objReader) init(f *os.File, p *Package) {
	r.f = f
	r.p = p
	r.offset, _ = f.Seek(0, io.SeekCurrent)
	r.limit, _ = f.Seek(0, io.SeekEnd)
	f.Seek(r.offset, io.SeekStart)
	r.b = bufio.NewReader(f)
	r.pkgprefix = objabi.PathToPrefix(p.ImportPath) + "."
}

// error records that an error occurred.
// It returns only the first error, so that an error
// caused by an earlier error does not discard information
// about the earlier error.
func (r *objReader) error(err error) error {
	if r.err == nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		r.err = err
	}
	// panic("corrupt") // useful for debugging
	return r.err
}

// peek returns the next n bytes without advancing the reader.
func (r *objReader) peek(n int) ([]byte, error) {
	if r.err != nil {
		return nil, r.err
	}
	if r.offset >= r.limit {
		r.error(io.ErrUnexpectedEOF)
		return nil, r.err
	}
	b, err := r.b.Peek(n)
	if err != nil {
		if err != bufio.ErrBufferFull {
			r.error(err)
		}
	}
	return b, err
}

// readByte reads and returns a byte from the input file.
// On I/O error or EOF, it records the error but returns byte 0.
// A sequence of 0 bytes will eventually terminate any
// parsing state in the object file. In particular, it ends the
// reading of a varint.
func (r *objReader) readByte() byte {
	if r.err != nil {
		return 0
	}
	if r.offset >= r.limit {
		r.error(io.ErrUnexpectedEOF)
		return 0
	}
	b, err := r.b.ReadByte()
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		r.error(err)
		b = 0
	} else {
		r.offset++
	}
	return b
}

// read reads exactly len(b) bytes from the input file.
// If an error occurs, read returns the error but also
// records it, so it is safe for callers to ignore the result
// as long as delaying the report is not a problem.
func (r *objReader) readFull(b []byte) error {
	if r.err != nil {
		return r.err
	}
	if r.offset+int64(len(b)) > r.limit {
		return r.error(io.ErrUnexpectedEOF)
	}
	n, err := io.ReadFull(r.b, b)
	r.offset += int64(n)
	if err != nil {
		return r.error(err)
	}
	return nil
}

// readInt reads a zigzag varint from the input file.
func (r *objReader) readInt() int64 {
	var u uint64

	for shift := uint(0); ; shift += 7 {
		if shift >= 64 {
			r.error(errCorruptObject)
			return 0
		}
		c := r.readByte()
		u |= uint64(c&0x7F) << shift
		if c&0x80 == 0 {
			break
		}
	}

	return int64(u>>1) ^ (int64(u) << 63 >> 63)
}

// readString reads a length-delimited string from the input file.
func (r *objReader) readString() string {
	n := r.readInt()
	buf := make([]byte, n)
	r.readFull(buf)
	return string(buf)
}

// readSymID reads a SymID from the input file.
func (r *objReader) readSymID() SymID {
	i := r.readInt()
	return r.p.SymRefs[i]
}

func (r *objReader) readRef() {
	name, abiOrStatic := r.readString(), r.readInt()

	// In a symbol name in an object file, "". denotes the
	// prefix for the package in which the object file has been found.
	// Expand it.
	name = strings.ReplaceAll(name, `"".`, r.pkgprefix)

	// The ABI field records either the ABI or -1 for static symbols.
	//
	// To distinguish different static symbols with the same name,
	// we use the symbol "version". Version 0 corresponds to
	// global symbols, and each file has a unique version > 0 for
	// all of its static symbols. The version is incremented on
	// each call to parseObject.
	//
	// For global symbols, we currently ignore the ABI.
	//
	// TODO(austin): Record the ABI in SymID. Since this is a
	// public API, we'll have to keep Version as 0 and record the
	// ABI in a new field (which differs from how the linker does
	// this, but that's okay). Show the ABI in things like
	// objdump.
	var vers int64
	if abiOrStatic == -1 {
		// Static symbol
		vers = r.p.MaxVersion
	}
	r.p.SymRefs = append(r.p.SymRefs, SymID{name, vers})
}

// readData reads a data reference from the input file.
func (r *objReader) readData() Data {
	n := r.readInt()
	d := Data{Offset: r.dataOffset, Size: n}
	r.dataOffset += n
	return d
}

// skip skips n bytes in the input.
func (r *objReader) skip(n int64) {
	if n < 0 {
		r.error(fmt.Errorf("debug/goobj: internal error: misuse of skip"))
	}
	if n < int64(len(r.tmp)) {
		// Since the data is so small, a just reading from the buffered
		// reader is better than flushing the buffer and seeking.
		r.readFull(r.tmp[:n])
	} else if n <= int64(r.b.Buffered()) {
		// Even though the data is not small, it has already been read.
		// Advance the buffer instead of seeking.
		for n > int64(len(r.tmp)) {
			r.readFull(r.tmp[:])
			n -= int64(len(r.tmp))
		}
		r.readFull(r.tmp[:n])
	} else {
		// Seek, giving up buffered data.
		_, err := r.f.Seek(r.offset+n, io.SeekStart)
		if err != nil {
			r.error(err)
		}
		r.offset += n
		r.b.Reset(r.f)
	}
}

// Parse parses an object file or archive from f,
// assuming that its import path is pkgpath.
func Parse(f *os.File, pkgpath string) (*Package, error) {
	if pkgpath == "" {
		pkgpath = `""`
	}
	p := new(Package)
	p.ImportPath = pkgpath

	var rd objReader
	rd.init(f, p)
	err := rd.readFull(rd.tmp[:8])
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}

	switch {
	default:
		return nil, errNotObject

	case bytes.Equal(rd.tmp[:8], archiveHeader):
		if err := rd.parseArchive(); err != nil {
			return nil, err
		}
	case bytes.Equal(rd.tmp[:8], goobjHeader):
		if err := rd.parseObject(goobjHeader); err != nil {
			return nil, err
		}
	}

	return p, nil
}

// trimSpace removes trailing spaces from b and returns the corresponding string.
// This effectively parses the form used in archive headers.
func trimSpace(b []byte) string {
	return string(bytes.TrimRight(b, " "))
}

// parseArchive parses a Unix archive of Go object files.
func (r *objReader) parseArchive() error {
	for r.offset < r.limit {
		if err := r.readFull(r.tmp[:60]); err != nil {
			return err
		}
		data := r.tmp[:60]

		// Each file is preceded by this text header (slice indices in first column):
		//	 0:16	name
		//	16:28 date
		//	28:34 uid
		//	34:40 gid
		//	40:48 mode
		//	48:58 size
		//	58:60 magic - `\n
		// We only care about name, size, and magic.
		// The fields are space-padded on the right.
		// The size is in decimal.
		// The file data - size bytes - follows the header.
		// Headers are 2-byte aligned, so if size is odd, an extra padding
		// byte sits between the file data and the next header.
		// The file data that follows is padded to an even number of bytes:
		// if size is odd, an extra padding byte is inserted betw the next header.
		if len(data) < 60 {
			return errTruncatedArchive
		}
		if !bytes.Equal(data[58:60], archiveMagic) {
			return errCorruptArchive
		}
		name := trimSpace(data[0:16])
		size, err := strconv.ParseInt(trimSpace(data[48:58]), 10, 64)
		if err != nil {
			return errCorruptArchive
		}
		data = data[60:]
		fsize := size + size&1
		if fsize < 0 || fsize < size {
			return errCorruptArchive
		}
		switch name {
		case "__.PKGDEF":
			r.skip(size)
		default:
			oldLimit := r.limit
			r.limit = r.offset + size

			p, err := r.peek(8)
			if err != nil {
				return err
			}
			if bytes.Equal(p, goobjHeader) {
				if err := r.parseObject(nil); err != nil {
					return fmt.Errorf("parsing archive member %q: %v", name, err)
				}
			} else {
				r.p.Native = append(r.p.Native, &NativeReader{
					Name:     name,
					ReaderAt: io.NewSectionReader(r.f, r.offset, size),
				})
			}

			r.skip(r.limit - r.offset)
			r.limit = oldLimit
		}
		if size&1 != 0 {
			r.skip(1)
		}
	}
	return nil
}

// parseObject parses a single Go object file.
// The prefix is the bytes already read from the file,
// typically in order to detect that this is an object file.
// The object file consists of a textual header ending in "\n!\n"
// and then the part we want to parse begins.
// The format of that part is defined in a comment at the top
// of src/liblink/objfile.c.
func (r *objReader) parseObject(prefix []byte) error {
	r.p.MaxVersion++
	h := make([]byte, 0, 256)
	h = append(h, prefix...)
	var c1, c2, c3 byte
	for {
		c1, c2, c3 = c2, c3, r.readByte()
		h = append(h, c3)
		// The new export format can contain 0 bytes.
		// Don't consider them errors, only look for r.err != nil.
		if r.err != nil {
			return errCorruptObject
		}
		if c1 == '\n' && c2 == '!' && c3 == '\n' {
			break
		}
	}

	hs := strings.Fields(string(h))
	if len(hs) >= 4 {
		r.p.Arch = hs[3]
	}
	// TODO: extract OS + build ID if/when we need it

	p, err := r.peek(8)
	if err != nil {
		return err
	}
	if !bytes.Equal(p, []byte(goobj2.Magic)) {
		return errNotObject
	}

	start := uint32(r.offset)

	length := r.limit - r.offset
	objbytes := make([]byte, length)
	r.readFull(objbytes)
	rr := goobj2.NewReaderFromBytes(objbytes, false)
	if rr == nil {
		return errCorruptObject
	}

	// Imports
	autolib := rr.Autolib()
	for _, p := range autolib {
		r.p.Imports = append(r.p.Imports, ImportedPkg{
			Pkg:         p.Pkg,
			Fingerprint: p.Fingerprint,
		})
	}

	// Referenced packages
	r.p.Packages = rr.Pkglist()

	// Dwarf file table
	r.p.DWARFFileList = make([]string, rr.NDwarfFile())
	for i := 0; i < len(r.p.DWARFFileList); i++ {
		r.p.DWARFFileList[i] = rr.DwarfFile(i)
	}

	// Name of referenced indexed symbols.
	nrefName := rr.NRefName()
	refNames := make(map[goobj2.SymRef]string, nrefName)
	for i := 0; i < nrefName; i++ {
		rn := rr.RefName(i)
		refNames[rn.Sym()] = rn.Name(rr)
	}

	abiToVer := func(abi uint16) int64 {
		var vers int64
		if abi == goobj2.SymABIstatic {
			// Static symbol
			vers = r.p.MaxVersion
		}
		return vers
	}

	resolveSymRef := func(s goobj2.SymRef) SymID {
		var i int
		switch p := s.PkgIdx; p {
		case goobj2.PkgIdxInvalid:
			if s.SymIdx != 0 {
				panic("bad sym ref")
			}
			return SymID{}
		case goobj2.PkgIdxNone:
			i = int(s.SymIdx) + rr.NSym()
		case goobj2.PkgIdxBuiltin:
			name, abi := goobj2.BuiltinName(int(s.SymIdx))
			return SymID{name, int64(abi)}
		case goobj2.PkgIdxSelf:
			i = int(s.SymIdx)
		default:
			return SymID{refNames[s], 0}
		}
		sym := rr.Sym(i)
		return SymID{sym.Name(rr), abiToVer(sym.ABI())}
	}

	// Read things for the current goobj API for now.

	// Symbols
	pcdataBase := start + rr.PcdataBase()
	n := rr.NSym() + rr.NNonpkgdef() + rr.NNonpkgref()
	ndef := rr.NSym() + rr.NNonpkgdef()
	for i := 0; i < n; i++ {
		osym := rr.Sym(i)
		if osym.Name(rr) == "" {
			continue // not a real symbol
		}
		// In a symbol name in an object file, "". denotes the
		// prefix for the package in which the object file has been found.
		// Expand it.
		name := strings.ReplaceAll(osym.Name(rr), `"".`, r.pkgprefix)
		symID := SymID{Name: name, Version: abiToVer(osym.ABI())}
		r.p.SymRefs = append(r.p.SymRefs, symID)

		if i >= ndef {
			continue // not a defined symbol from here
		}

		// Symbol data
		dataOff := rr.DataOff(i)
		siz := int64(rr.DataSize(i))

		sym := Sym{
			SymID: symID,
			Kind:  objabi.SymKind(osym.Type()),
			DupOK: osym.Dupok(),
			Size:  int64(osym.Siz()),
			Data:  Data{int64(start + dataOff), siz},
		}
		r.p.Syms = append(r.p.Syms, &sym)

		// Reloc
		relocs := rr.Relocs(i)
		sym.Reloc = make([]Reloc, len(relocs))
		for j := range relocs {
			rel := &relocs[j]
			sym.Reloc[j] = Reloc{
				Offset: int64(rel.Off()),
				Size:   int64(rel.Siz()),
				Type:   objabi.RelocType(rel.Type()),
				Add:    rel.Add(),
				Sym:    resolveSymRef(rel.Sym()),
			}
		}

		// Aux symbol info
		isym := -1
		funcdata := make([]goobj2.SymRef, 0, 4)
		auxs := rr.Auxs(i)
		for j := range auxs {
			a := &auxs[j]
			switch a.Type() {
			case goobj2.AuxGotype:
				sym.Type = resolveSymRef(a.Sym())
			case goobj2.AuxFuncInfo:
				if a.Sym().PkgIdx != goobj2.PkgIdxSelf {
					panic("funcinfo symbol not defined in current package")
				}
				isym = int(a.Sym().SymIdx)
			case goobj2.AuxFuncdata:
				funcdata = append(funcdata, a.Sym())
			case goobj2.AuxDwarfInfo, goobj2.AuxDwarfLoc, goobj2.AuxDwarfRanges, goobj2.AuxDwarfLines:
				// nothing to do
			default:
				panic("unknown aux type")
			}
		}

		// Symbol Info
		if isym == -1 {
			continue
		}
		b := rr.BytesAt(rr.DataOff(isym), rr.DataSize(isym))
		info := goobj2.FuncInfo{}
		info.Read(b)

		info.Pcdata = append(info.Pcdata, info.PcdataEnd) // for the ease of knowing where it ends
		f := &Func{
			Args:     int64(info.Args),
			Frame:    int64(info.Locals),
			NoSplit:  osym.NoSplit(),
			Leaf:     osym.Leaf(),
			TopFrame: osym.TopFrame(),
			PCSP:     Data{int64(pcdataBase + info.Pcsp), int64(info.Pcfile - info.Pcsp)},
			PCFile:   Data{int64(pcdataBase + info.Pcfile), int64(info.Pcline - info.Pcfile)},
			PCLine:   Data{int64(pcdataBase + info.Pcline), int64(info.Pcinline - info.Pcline)},
			PCInline: Data{int64(pcdataBase + info.Pcinline), int64(info.Pcdata[0] - info.Pcinline)},
			PCData:   make([]Data, len(info.Pcdata)-1), // -1 as we appended one above
			FuncData: make([]FuncData, len(info.Funcdataoff)),
			File:     make([]string, len(info.File)),
			InlTree:  make([]InlinedCall, len(info.InlTree)),
		}
		sym.Func = f
		for k := range f.PCData {
			f.PCData[k] = Data{int64(pcdataBase + info.Pcdata[k]), int64(info.Pcdata[k+1] - info.Pcdata[k])}
		}
		for k := range f.FuncData {
			symID := resolveSymRef(funcdata[k])
			f.FuncData[k] = FuncData{symID, int64(info.Funcdataoff[k])}
		}
		for k := range f.File {
			symID := resolveSymRef(info.File[k])
			f.File[k] = symID.Name
		}
		for k := range f.InlTree {
			inl := &info.InlTree[k]
			f.InlTree[k] = InlinedCall{
				Parent:   int64(inl.Parent),
				File:     resolveSymRef(inl.File).Name,
				Line:     int64(inl.Line),
				Func:     resolveSymRef(inl.Func),
				ParentPC: int64(inl.ParentPC),
			}
		}
	}

	return nil
}

func (r *Reloc) String(insnOffset uint64) string {
	delta := r.Offset - int64(insnOffset)
	s := fmt.Sprintf("[%d:%d]%s", delta, delta+r.Size, r.Type)
	if r.Sym.Name != "" {
		if r.Add != 0 {
			return fmt.Sprintf("%s:%s+%d", s, r.Sym.Name, r.Add)
		}
		return fmt.Sprintf("%s:%s", s, r.Sym.Name)
	}
	if r.Add != 0 {
		return fmt.Sprintf("%s:%d", s, r.Add)
	}
	return s
}
