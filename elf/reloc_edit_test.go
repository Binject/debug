package elf

import (
	"bytes"
	"path"
	"testing"
)

func TestAddRelocationCreatesRelaText(t *testing.T) {
	f, err := Open(path.Join("testdata", "gcc-amd64-linux-exec"))
	if err != nil {
		t.Fatalf("open elf: %v", err)
	}
	defer f.Close()

	syms, err := f.Symbols()
	if err != nil {
		t.Fatalf("symbols: %v", err)
	}
	var symName string
	for _, sym := range syms {
		if sym.Name != "" && sym.Section != SHN_UNDEF {
			symName = sym.Name
			break
		}
	}
	if symName == "" {
		t.Fatalf("no suitable symbol found")
	}

	addend := int64(0)
	if err := f.AddRelocationForSymbol(".text", symName, 0, uint32(R_X86_64_64), &addend); err != nil {
		t.Fatalf("add relocation: %v", err)
	}

	out, err := f.Bytes()
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	f2, err := NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}

	rel := f2.Section(".rela.text")
	if rel == nil {
		t.Fatalf("rela.text not found")
	}
	if rel.Size == 0 || rel.Entsize == 0 || rel.Size%rel.Entsize != 0 {
		t.Fatalf("rela.text size invalid: size=%d entsize=%d", rel.Size, rel.Entsize)
	}
}

func TestAddDynamicRelocationUpdatesTags(t *testing.T) {
	f, err := Open(path.Join("testdata", "gcc-amd64-linux-exec"))
	if err != nil {
		t.Fatalf("open elf: %v", err)
	}
	defer f.Close()

	relDyn := f.Section(".rela.dyn")
	if relDyn == nil {
		t.Fatalf("rela.dyn missing in test binary")
	}
	origSize := relDyn.Size
	rel := Rela64{
		Off:    0,
		Info:   R_INFO(0, uint32(R_X86_64_RELATIVE)),
		Addend: 0,
	}
	if err := f.AddRelocationsToRelocSection(".rela.dyn", []Rela64{rel}); err != nil {
		t.Fatalf("add to rela.dyn: %v", err)
	}

	out, err := f.Bytes()
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	f2, err := NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}

	relDyn2 := f2.Section(".rela.dyn")
	if relDyn2 == nil || relDyn2.Size <= origSize {
		t.Fatalf("rela.dyn not grown")
	}

	dynTags := map[DynTag]uint64{}
	for _, tag := range f2.DynTags {
		dynTags[tag.Tag] = tag.Value
	}
	if dynTags[DT_RELA] != relDyn2.Addr {
		t.Fatalf("DT_RELA not updated")
	}
	if dynTags[DT_RELASZ] != relDyn2.Size {
		t.Fatalf("DT_RELASZ not updated")
	}
	if dynTags[DT_RELAENT] != relDyn2.Entsize {
		t.Fatalf("DT_RELAENT not updated")
	}
}

func TestAddRelocationCreatesRelText(t *testing.T) {
	f, err := Open(path.Join("testdata", "gcc-amd64-linux-exec"))
	if err != nil {
		t.Fatalf("open elf: %v", err)
	}
	defer f.Close()

	if err := f.AddRelocationForAddr(".text", 0, uint32(R_X86_64_64), nil); err != nil {
		t.Fatalf("add relocation: %v", err)
	}
	out, err := f.Bytes()
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	f2, err := NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	rel := f2.Section(".rel.text")
	if rel == nil {
		t.Fatalf("rel.text not found")
	}
	if rel.Size == 0 || rel.Entsize == 0 || rel.Size%rel.Entsize != 0 {
		t.Fatalf("rel.text size invalid: size=%d entsize=%d", rel.Size, rel.Entsize)
	}
}

func TestPltRelocationUpdatesTags(t *testing.T) {
	f, err := Open(path.Join("testdata", "gcc-amd64-linux-exec"))
	if err != nil {
		t.Fatalf("open elf: %v", err)
	}
	defer f.Close()

	relPlt := f.Section(".rela.plt")
	if relPlt == nil {
		t.Skip("no .rela.plt section in test binary")
	}
	origSize := relPlt.Size
	rel := Rela64{
		Off:    0,
		Info:   R_INFO(0, uint32(R_X86_64_JMP_SLOT)),
		Addend: 0,
	}
	if err := f.AddRelocationsToRelocSection(".rela.plt", []Rela64{rel}); err != nil {
		t.Fatalf("add to rela.plt: %v", err)
	}

	out, err := f.Bytes()
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	f2, err := NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	relPlt2 := f2.Section(".rela.plt")
	if relPlt2 == nil || relPlt2.Size <= origSize {
		t.Fatalf("rela.plt not grown")
	}
	dynTags := map[DynTag]uint64{}
	for _, tag := range f2.DynTags {
		dynTags[tag.Tag] = tag.Value
	}
	if dynTags[DT_JMPREL] != relPlt2.Addr {
		t.Fatalf("DT_JMPREL not updated")
	}
	if dynTags[DT_PLTRELSZ] != relPlt2.Size {
		t.Fatalf("DT_PLTRELSZ not updated")
	}
	if dynTags[DT_PLTREL] != uint64(DT_RELA) {
		t.Fatalf("DT_PLTREL not updated")
	}
}

func TestRemoveRelocationsFromSection(t *testing.T) {
	f, err := Open(path.Join("testdata", "gcc-amd64-linux-exec"))
	if err != nil {
		t.Fatalf("open elf: %v", err)
	}
	defer f.Close()

	addend := int64(0)
	syms, err := f.Symbols()
	if err != nil {
		t.Fatalf("symbols: %v", err)
	}
	var symName string
	for _, sym := range syms {
		if sym.Name != "" && sym.Section != SHN_UNDEF {
			symName = sym.Name
			break
		}
	}
	if symName == "" {
		t.Skip("no suitable symbol found")
	}
	if err := f.AddRelocationForSymbol(".text", symName, 0, uint32(R_X86_64_64), &addend); err != nil {
		t.Fatalf("add relocation: %v", err)
	}
	if err := f.RemoveRelocations(f.Section(".text")); err != nil {
		t.Fatalf("remove relocations: %v", err)
	}
	out, err := f.Bytes()
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	f2, err := NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if sec := f2.Section(".rela.text"); sec != nil && sec.Size != 0 {
		t.Fatalf("expected .rela.text cleared")
	}
	if sec := f2.Section(".rel.text"); sec != nil && sec.Size != 0 {
		t.Fatalf("expected .rel.text cleared")
	}
}
