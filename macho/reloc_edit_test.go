package macho

import (
	"bytes"
	"path"
	"testing"
)

func TestDyldInfoGeneratedFromRelocs(t *testing.T) {
	f, err := Open(path.Join("testdata", "gcc-amd64-darwin-exec"))
	if err != nil {
		t.Fatalf("open macho: %v", err)
	}
	defer f.Close()

	if f.DylinkInfo == nil {
		t.Skip("no dyld info present")
	}
	sec := f.Section("__text")
	if sec == nil {
		t.Fatalf("missing __text section")
	}
	origCount := len(sec.Relocs)
	if err := f.AddRelocation("__text", Reloc{Addr: 0, Type: 0, Len: 3, Pcrel: false, Extern: false}); err != nil {
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
	sec2 := f2.Section("__text")
	if sec2 == nil || len(sec2.Relocs) != origCount+1 {
		t.Fatalf("relocations not persisted")
	}
	if sec2.Reloff == 0 || sec2.Nreloc == 0 {
		t.Fatalf("section relocation offsets not updated")
	}
	if f2.DylinkInfo == nil || f2.DylinkInfo.RebaseLen == 0 {
		t.Fatalf("dyld rebase info not generated")
	}
}

func TestDyldBindOrdinal(t *testing.T) {
	f, err := Open(path.Join("testdata", "gcc-amd64-darwin-exec"))
	if err != nil {
		t.Fatalf("open macho: %v", err)
	}
	defer f.Close()

	if f.DylinkInfo == nil || f.Symtab == nil {
		t.Skip("missing dyld info or symbol table")
	}
	sec := f.Section("__text")
	if sec == nil {
		t.Fatalf("missing __text section")
	}

	var symName string
	for _, sym := range f.Symtab.Syms {
		if sym.Name != "" {
			symName = sym.Name
			break
		}
	}
	if symName == "" {
		t.Skip("no suitable symbol found")
	}

	if err := f.AddRelocationForSymbolWithDylibOrdinal("__text", symName, 0, 0, 3, false, 1); err != nil {
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
	if f2.DylinkInfo == nil || len(f2.DylinkInfo.BindingInfoDat) == 0 {
		t.Fatalf("missing binding info")
	}
	ordinalOpcode := byte(bindOpcodeSetDylibOrdinalImm | 1)
	if !bytes.Contains(f2.DylinkInfo.BindingInfoDat, []byte{ordinalOpcode}) {
		t.Fatalf("bind info missing ordinal opcode")
	}
}
