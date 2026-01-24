package pe

import (
	"bytes"
	"path"
	"testing"
)

func TestAddBaseAndSectionRelocations(t *testing.T) {
	f, err := Open(path.Join("testdata", "gcc-386-mingw-exec"))
	if err != nil {
		t.Fatalf("open pe: %v", err)
	}
	defer f.Close()

	if len(f.Sections) == 0 {
		t.Fatalf("no sections")
	}
	text := f.Sections[0]
	f.AddBaseReloc(text.VirtualAddress, IMAGE_REL_BASED_HIGHLOW)
	if err := f.AddSectionRelocation(text.Name, Reloc{VirtualAddress: 0, SymbolTableIndex: 0, Type: 0}); err != nil {
		t.Fatalf("add section reloc: %v", err)
	}

	out, err := f.Bytes()
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	f2, err := NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if f2.BaseRelocationTable == nil || len(*f2.BaseRelocationTable) == 0 {
		t.Fatalf("base relocations not written")
	}

	var dd DataDirectory
	switch hdr := f2.OptionalHeader.(type) {
	case *OptionalHeader32:
		dd = hdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
	case *OptionalHeader64:
		dd = hdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
	default:
		t.Fatalf("missing optional header")
	}
	if dd.Size == 0 {
		t.Fatalf("base relocation directory not updated")
	}

	sec2 := f2.Section(text.Name)
	if sec2 == nil || len(sec2.Relocs) == 0 {
		t.Fatalf("section relocations not written")
	}
	if sec2.PointerToRelocations == 0 || sec2.NumberOfRelocations == 0 {
		t.Fatalf("section relocation pointers not updated")
	}
	if f2.FileHeader.Characteristics&IMAGE_FILE_RELOCS_STRIPPED != 0 {
		t.Fatalf("relocs stripped flag still set")
	}
}
