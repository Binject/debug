package elf

import "testing"

func TestDynValuesReadsProgramHeader(t *testing.T) {
	f, err := Open("testdata/gcc-amd64-linux-exec")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	vals, err := f.DynValues()
	if err != nil {
		t.Fatal(err)
	}
	var needed int
	for _, v := range vals {
		if v.Tag == DT_NEEDED {
			needed++
		}
	}
	if needed == 0 {
		t.Fatalf("DT_NEEDED missing from %d tags", len(vals))
	}
}

func TestDynValuesRejectsHugeProgramHeader(t *testing.T) {
	f := &File{FileHeader: FileHeader{Class: ELFCLASS64}}
	f.Progs = []*Prog{{
		ProgHeader: ProgHeader{Type: PT_DYNAMIC, Filesz: uint64(maxDynamicEntries*16) + 16},
	}}
	if _, err := f.DynValues(); err == nil {
		t.Fatal("huge PT_DYNAMIC was accepted")
	}
}
