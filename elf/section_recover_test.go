package elf

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// elf64WithLoad is a tiny executable whose program header is readable.
// shoff, shnum, and shstrndx describe the section table, which may be junk.
func elf64WithLoad(shoff uint64, shnum, shstrndx uint16) []byte {
	const (
		ehsize    = 64
		phentsize = 56
		phnum     = 1
	)
	buf := make([]byte, ehsize+phentsize)
	buf[0], buf[1], buf[2], buf[3] = 0x7f, 'E', 'L', 'F'
	buf[4] = byte(ELFCLASS64)
	buf[5] = byte(ELFDATA2LSB)
	buf[6] = byte(EV_CURRENT)
	binary.LittleEndian.PutUint16(buf[16:], uint16(ET_EXEC))
	binary.LittleEndian.PutUint16(buf[18:], uint16(EM_X86_64))
	binary.LittleEndian.PutUint32(buf[20:], uint32(EV_CURRENT))
	binary.LittleEndian.PutUint64(buf[24:], 0x400000)
	binary.LittleEndian.PutUint64(buf[32:], ehsize)
	binary.LittleEndian.PutUint64(buf[40:], shoff)
	binary.LittleEndian.PutUint16(buf[52:], ehsize)
	binary.LittleEndian.PutUint16(buf[54:], phentsize)
	binary.LittleEndian.PutUint16(buf[56:], phnum)
	binary.LittleEndian.PutUint16(buf[58:], 64)
	binary.LittleEndian.PutUint16(buf[60:], shnum)
	binary.LittleEndian.PutUint16(buf[62:], shstrndx)
	// PT_LOAD, PF_R|PF_X, covers the file, entry at 0x400000.
	ph := buf[ehsize:]
	binary.LittleEndian.PutUint32(ph[0:], uint32(PT_LOAD))
	binary.LittleEndian.PutUint32(ph[4:], uint32(PF_R|PF_X))
	binary.LittleEndian.PutUint64(ph[16:], 0x400000)
	binary.LittleEndian.PutUint64(ph[24:], 0x400000)
	binary.LittleEndian.PutUint64(ph[32:], uint64(len(buf)))
	binary.LittleEndian.PutUint64(ph[40:], uint64(len(buf)))
	binary.LittleEndian.PutUint64(ph[48:], 0x1000)
	return buf
}

func TestMissingSectionTableKeepsLoads(t *testing.T) {
	raw := elf64WithLoad(1<<20, 4, 1)
	f, err := NewFile(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if f.Entry != 0x400000 {
		t.Fatalf("entry %#x", f.Entry)
	}
	if len(f.Progs) != 1 || f.Progs[0].Type != PT_LOAD {
		t.Fatalf("progs %+v", f.Progs)
	}
	if len(f.Sections) != 0 {
		t.Fatalf("sections kept: %d", len(f.Sections))
	}
}

func TestBadSectionNamesKeepLoads(t *testing.T) {
	raw := elf64WithLoad(64+56, 1, 0)
	// One section header of zeros sits right after the program header.
	// Its name index is 0 and the string table is empty, so the name does not resolve.
	raw = append(raw, make([]byte, 64)...)
	// Name index 1 into an empty string table does not resolve.
	binary.LittleEndian.PutUint32(raw[64+56:], 1)
	f, err := NewFile(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Progs) != 1 || f.Entry != 0x400000 {
		t.Fatalf("entry %#x progs %d", f.Entry, len(f.Progs))
	}
	if len(f.Sections) != 0 {
		t.Fatalf("unnamed sections kept: %d", len(f.Sections))
	}
}

func TestTooManyProgramHeadersIsAnError(t *testing.T) {
	raw := elf64WithLoad(0, 0, 0)
	binary.LittleEndian.PutUint16(raw[56:], 0xffff) // PN_XNUM
	if _, err := NewFile(bytes.NewReader(raw)); err == nil {
		t.Fatal("expected an error for PN_XNUM without a real count")
	}
}
