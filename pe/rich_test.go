package pe

import (
	"encoding/binary"
	"testing"
)

func TestRichEntriesDecodes(t *testing.T) {
	key := uint32(0x11223344)
	var raw []byte
	put := func(v uint32) {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], v^key)
		raw = append(raw, b[:]...)
	}
	put(binary.LittleEndian.Uint32([]byte("DanS")))
	put(0)
	put(0)
	put(0)
	put(uint32(0x0102)<<16 | 0x0304)
	put(7)
	raw = append(raw, "Rich"...)
	var kb [4]byte
	binary.LittleEndian.PutUint32(kb[:], key)
	raw = append(raw, kb[:]...)

	f := &File{RichHeader: raw}
	ents, err := f.RichEntries()
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].ToolID != 0x0102 || ents[0].Version != 0x0304 || ents[0].Count != 7 {
		t.Fatalf("%+v", ents)
	}
}

func TestRichEntriesRejectsHugeHeader(t *testing.T) {
	f := &File{RichHeader: make([]byte, 1<<20+1)}
	if _, err := f.RichEntries(); err == nil {
		t.Fatal("huge rich header was accepted")
	}
}
