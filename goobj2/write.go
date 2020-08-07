// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Writing Go object files.

package goobj2

import (
	"path/filepath"
	"strings"

	"github.com/Binject/debug/goobj2/internal/bio"
	"github.com/Binject/debug/goobj2/internal/goobj2"
	"github.com/Binject/debug/goobj2/internal/objabi"
)

// Entry point of writing new object file.
func WriteObjFile2(ctxt *Package, b *bio.Writer, pkgpath string) {

	//genFuncInfoSyms(ctxt)

	w := writer{
		Writer:  goobj2.NewWriter(b),
		ctxt:    ctxt,
		pkgpath: objabi.PathToPrefix(pkgpath),
	}

	//start := b.Offset()

	// Header
	// We just reserve the space. We'll fill in the offsets later.
	ctxt.Header.Write(w.Writer)

	// String table
	w.StringTable()

	// Autolib
	ctxt.Header.Offsets[goobj2.BlkAutolib] = w.Offset()
	for i := range ctxt.Imports {
		ctxt.Imports[i].Write(w.Writer)
	}

	// Package references
	ctxt.Header.Offsets[goobj2.BlkPkgIdx] = w.Offset()
	for _, pkg := range ctxt.Packages {
		w.StringRef(pkg)
	}

	// DWARF file table
	ctxt.Header.Offsets[goobj2.BlkDwarfFile] = w.Offset()
	for _, f := range ctxt.DWARFFileList {
		w.StringRef(filepath.ToSlash(f))
	}

	// Symbol definitions
	ctxt.Header.Offsets[goobj2.BlkSymdef] = w.Offset()
	for _, s := range ctxt.SymDefs {
		w.Sym(s)
	}

	// Non-pkg symbol definitions
	ctxt.Header.Offsets[goobj2.BlkNonpkgdef] = w.Offset()
	for _, s := range ctxt.NonPkgSymDefs {
		w.Sym(s)
	}

	// Non-pkg symbol references
	ctxt.Header.Offsets[goobj2.BlkNonpkgref] = w.Offset()
	for _, s := range ctxt.NonPkgSymRefs {
		w.Sym(s)
	}

	// Reloc indexes
	ctxt.Header.Offsets[goobj2.BlkRelocIdx] = w.Offset()
	nreloc := uint32(0)
	lists := [][]*Sym{ctxt.SymDefs, ctxt.NonPkgSymDefs}
	for _, list := range lists {
		for _, s := range list {
			w.Uint32(nreloc)
			nreloc += uint32(len(s.Reloc))
		}
	}
	w.Uint32(nreloc)

	// Symbol Info indexes
	/*ctxt.Header.Offsets[goobj2.BlkAuxIdx] = w.Offset()
	naux := uint32(0)
	for _, list := range lists {
		for _, s := range list {
			w.Uint32(naux)
			naux += uint32(nAuxSym(s))
		}
	}
	w.Uint32(naux)*/

	// Data indexes
	ctxt.Header.Offsets[goobj2.BlkDataIdx] = w.Offset()
	dataOff := uint32(0)
	for _, list := range lists {
		for _, s := range list {
			w.Uint32(dataOff)
			dataOff += uint32(len(s.Data))
		}
	}
	w.Uint32(dataOff)

	// Relocs
	/*ctxt.Header.Offsets[goobj2.BlkReloc] = w.Offset()
	for _, list := range lists {
		for _, s := range list {
			for i := range s.R {
				w.Reloc(&s.R[i])
			}
		}
	}

	// Aux symbol info
	ctxt.Header.Offsets[goobj2.BlkAux] = w.Offset()
	for _, list := range lists {
		for _, s := range list {
			w.Aux(s)
		}
	}*/

	// Data
	ctxt.Header.Offsets[goobj2.BlkData] = w.Offset()
	for _, list := range lists {
		for _, s := range list {
			w.Bytes(s.Data)
		}
	}

	// Pcdata
	/*ctxt.Header.Offsets[goobj2.BlkPcdata] = w.Offset()
	for _, s := range ctxt.Text { // iteration order must match genFuncInfoSyms
		if s.Func != nil {
			pc := &s.Func.Pcln
			w.Bytes(pc.Pcsp.P)
			w.Bytes(pc.Pcfile.P)
			w.Bytes(pc.Pcline.P)
			w.Bytes(pc.Pcinline.P)
			for i := range pc.Pcdata {
				w.Bytes(pc.Pcdata[i].P)
			}
		}
	}

	// Blocks used only by tools (objdump, nm).

	// Referenced symbol names from other packages
	ctxt.Header.Offsets[goobj2.BlkRefName] = w.Offset()
	w.refNames()

	ctxt.Header.Offsets[goobj2.BlkEnd] = w.Offset()

	// Fix up block offsets in the header
	end := start + int64(w.Offset())
	b.MustSeek(start, 0)
	ctxt.Header.Write(w.Writer)
	b.MustSeek(end, 0)*/
}

type writer struct {
	*goobj2.Writer
	ctxt    *Package
	pkgpath string   // the package import path (escaped), "" if unknown
	pkglist []string // list of packages referenced, indexed by ctxt.pkgIdx
}

func (w *writer) StringTable() {
	w.AddString("")
	for _, p := range w.ctxt.Imports {
		w.AddString(p.Pkg)
	}
	for _, pkg := range w.ctxt.Packages {
		w.AddString(pkg)
	}

	syms := [][]*Sym{w.ctxt.SymDefs, w.ctxt.NonPkgSymDefs, w.ctxt.NonPkgSymRefs}
	for _, list := range syms {
		for _, s := range list {
			// TODO: this includes references of indexed symbols from other packages,
			// for which the linker doesn't need the name. Consider moving them to
			// a separate block (for tools only).
			if w.pkgpath != "" {
				s.Name = strings.Replace(s.Name, "\"\".", w.pkgpath+".", -1)
			}
			w.AddString(s.Name)
		}
	}

	/*for i, list := range syms {
		// skip non-pkg symbol references
		if i == 2 {
			break
		}

		for _, s := range list {
			if s.Kind != objabi.STEXT {
				return
			}
			pc := &s.Func.Pcln
			for _, f := range pc.File {
				w.AddString(filepath.ToSlash(f))
			}
			for _, call := range pc.InlTree.nodes {
				f, _ := linkgetlineFromPos(w.ctxt, call.Pos)
				w.AddString(filepath.ToSlash(f))
			}
		}
	}*/

	for _, f := range w.ctxt.DWARFFileList {
		w.AddString(filepath.ToSlash(f))
	}
}

func (w *writer) Sym(s *Sym) {
	name := s.Name
	if strings.HasPrefix(name, "gofile..") {
		name = filepath.ToSlash(name)
	}
	var align uint32
	if s.Func != nil {
		align = uint32(s.Func.Align)
	}
	var o goobj2.Sym
	o.SetName(name, w.Writer)
	o.SetABI(s.ABI)
	o.SetType(uint8(s.Kind))
	o.SetFlag(s.Flag)
	o.SetSiz(uint32(s.Size))
	o.SetAlign(align)
	o.Write(w.Writer)
}

/*func makeSymRef(s *LSym) goobj2.SymRef {
	if s == nil {
		return goobj2.SymRef{}
	}
	if s.PkgIdx == 0 || !s.Indexed() {
		fmt.Printf("unindexed symbol reference: %v\n", s)
		panic("unindexed symbol reference")
	}
	return goobj2.SymRef{PkgIdx: uint32(s.PkgIdx), SymIdx: uint32(s.SymIdx)}
}

func (w *writer) Reloc(r *Reloc) {
	var o goobj2.Reloc
	o.SetOff(int32(r.Offset))
	o.SetSiz(uint8(r.Size))
	o.SetType(uint8(r.Type))
	o.SetAdd(r.Add)
	o.SetSym(makeSymRef(r.Sym))
	o.Write(w.Writer)
}

func (w *writer) aux1(typ uint8, rs *LSym) {
	var o goobj2.Aux
	o.SetType(typ)
	o.SetSym(makeSymRef(rs))
	o.Write(w.Writer)
}

func (w *writer) Aux(s *LSym) {
	if s.Gotype != nil {
		w.aux1(goobj2.AuxGotype, s.Gotype)
	}
	if s.Func != nil {
		w.aux1(goobj2.AuxFuncInfo, s.Func.FuncInfoSym)

		for _, d := range s.Func.Pcln.Funcdata {
			w.aux1(goobj2.AuxFuncdata, d)
		}

		if s.Func.dwarfInfoSym != nil && s.Func.dwarfInfoSym.Size != 0 {
			w.aux1(goobj2.AuxDwarfInfo, s.Func.dwarfInfoSym)
		}
		if s.Func.dwarfLocSym != nil && s.Func.dwarfLocSym.Size != 0 {
			w.aux1(goobj2.AuxDwarfLoc, s.Func.dwarfLocSym)
		}
		if s.Func.dwarfRangesSym != nil && s.Func.dwarfRangesSym.Size != 0 {
			w.aux1(goobj2.AuxDwarfRanges, s.Func.dwarfRangesSym)
		}
		if s.Func.dwarfDebugLinesSym != nil && s.Func.dwarfDebugLinesSym.Size != 0 {
			w.aux1(goobj2.AuxDwarfLines, s.Func.dwarfDebugLinesSym)
		}
	}
}

// Emits names of referenced indexed symbols, used by tools (objdump, nm)
// only.
func (w *writer) refNames() {
	seen := make(map[goobj2.SymRef]bool)
	w.ctxt.traverseSyms(traverseRefs, func(rs *LSym) { // only traverse refs, not auxs, as tools don't need auxs
		switch rs.PkgIdx {
		case goobj2.PkgIdxNone, goobj2.PkgIdxBuiltin, goobj2.PkgIdxSelf: // not an external indexed reference
			return
		case goobj2.PkgIdxInvalid:
			panic("unindexed symbol reference")
		}
		symref := makeSymRef(rs)
		if seen[symref] {
			return
		}
		seen[symref] = true
		var o goobj2.RefName
		o.SetSym(symref)
		o.SetName(rs.Name, w.Writer)
		o.Write(w.Writer)
	})
	// TODO: output in sorted order?
	// Currently tools (cmd/internal/goobj package) doesn't use mmap,
	// and it just read it into a map in memory upfront. If it uses
	// mmap, if the output is sorted, it probably could avoid reading
	// into memory and just do lookups in the mmap'd object file.
}

// return the number of aux symbols s have.
func nAuxSym(s *LSym) int {
	n := 0
	if s.Gotype != nil {
		n++
	}
	if s.Func != nil {
		// FuncInfo is an aux symbol, each Funcdata is an aux symbol
		n += 1 + len(s.Func.Pcln.Funcdata)
		if s.Func.dwarfInfoSym != nil && s.Func.dwarfInfoSym.Size != 0 {
			n++
		}
		if s.Func.dwarfLocSym != nil && s.Func.dwarfLocSym.Size != 0 {
			n++
		}
		if s.Func.dwarfRangesSym != nil && s.Func.dwarfRangesSym.Size != 0 {
			n++
		}
		if s.Func.dwarfDebugLinesSym != nil && s.Func.dwarfDebugLinesSym.Size != 0 {
			n++
		}
	}
	return n
}

// generate symbols for FuncInfo.
func genFuncInfoSyms(ctxt *Package) {
	infosyms := make([]*Sym, 0, len(ctxt.Text))
	var pcdataoff uint32
	var b bytes.Buffer
	symidx := int32(len(ctxt.SymDefs))
	for _, s := range ctxt.Text {
		if s.Func == nil {
			continue
		}
		o := goobj2.FuncInfo{
			Args:   uint32(s.Func.Args),
			Locals: uint32(s.Func.Locals),
		}
		pc := &s.Func.Pcln
		o.Pcsp = pcdataoff
		pcdataoff += uint32(len(pc.Pcsp.P))
		o.Pcfile = pcdataoff
		pcdataoff += uint32(len(pc.Pcfile.P))
		o.Pcline = pcdataoff
		pcdataoff += uint32(len(pc.Pcline.P))
		o.Pcinline = pcdataoff
		pcdataoff += uint32(len(pc.Pcinline.P))
		o.Pcdata = make([]uint32, len(pc.Pcdata))
		for i, pcd := range pc.Pcdata {
			o.Pcdata[i] = pcdataoff
			pcdataoff += uint32(len(pcd.P))
		}
		o.PcdataEnd = pcdataoff
		o.Funcdataoff = make([]uint32, len(pc.Funcdataoff))
		for i, x := range pc.Funcdataoff {
			o.Funcdataoff[i] = uint32(x)
		}
		o.File = make([]goobj2.SymRef, len(pc.File))
		for i, f := range pc.File {
			fsym := ctxt.Lookup(f)
			o.File[i] = makeSymRef(fsym)
		}
		o.InlTree = make([]goobj2.InlTreeNode, len(pc.InlTree.nodes))
		for i, inl := range pc.InlTree.nodes {
			f, l := linkgetlineFromPos(ctxt, inl.Pos)
			fsym := ctxt.Lookup(f)
			o.InlTree[i] = goobj2.InlTreeNode{
				Parent:   int32(inl.Parent),
				File:     makeSymRef(fsym),
				Line:     l,
				Func:     makeSymRef(inl.Func),
				ParentPC: inl.ParentPC,
			}
		}

		o.Write(&b)
		isym := &LSym{
			Type:   objabi.SDATA, // for now, I don't think it matters
			PkgIdx: goobj2.PkgIdxSelf,
			SymIdx: symidx,
			P:      append([]byte(nil), b.Bytes()...),
		}
		isym.Set(AttrIndexed, true)
		symidx++
		infosyms = append(infosyms, isym)
		s.Func.FuncInfoSym = isym
		b.Reset()

		dwsyms := []*LSym{s.Func.dwarfRangesSym, s.Func.dwarfLocSym, s.Func.dwarfDebugLinesSym, s.Func.dwarfInfoSym}
		for _, s := range dwsyms {
			if s == nil || s.Size == 0 {
				continue
			}
			s.PkgIdx = goobj2.PkgIdxSelf
			s.SymIdx = symidx
			s.Set(AttrIndexed, true)
			symidx++
			infosyms = append(infosyms, s)
		}
	}
	ctxt.defs = append(ctxt.defs, infosyms...)
}
*/
