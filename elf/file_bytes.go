package elf

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io/ioutil"
	"log"
)

// Bytes - returns the bytes of an Elf file
func (f *File) Bytes() ([]byte, error) {

	bytesWritten := uint64(0)
	buf := bytes.NewBuffer(nil)
	w := bufio.NewWriter(buf)

	// Write Elf Magic
	w.WriteByte('\x7f')
	w.WriteByte('E')
	w.WriteByte('L')
	w.WriteByte('F')
	bytesWritten += 4

	w.WriteByte(byte(f.Class))
	w.WriteByte(byte(f.Data))
	w.WriteByte(byte(f.Version))
	w.WriteByte(byte(f.OSABI))
	w.WriteByte(byte(f.ABIVersion))
	// ident[EI_PAD] ( 7 bytes )
	w.Write([]byte{0, 0, 0, 0, 0, 0, 0})
	bytesWritten += 12

	binary.Write(w, f.ByteOrder, uint16(f.Type))
	binary.Write(w, f.ByteOrder, uint16(f.Machine))
	binary.Write(w, f.ByteOrder, uint32(f.Version))
	bytesWritten += 8

	switch f.Class {
	case ELFCLASS32:
		binary.Write(w, f.ByteOrder, uint32(f.Entry))
		binary.Write(w, f.ByteOrder, uint32(f.ELFHeader32.Phoff))
		binary.Write(w, f.ByteOrder, int32(f.ELFHeader32.Shoff))
		binary.Write(w, f.ByteOrder, uint32(f.ELFHeader32.Flags))
		binary.Write(w, f.ByteOrder, uint16(f.ELFHeader32.Ehsize))
		binary.Write(w, f.ByteOrder, uint16(f.ELFHeader32.Phentsize))
		binary.Write(w, f.ByteOrder, uint16(len(f.Progs)))
		binary.Write(w, f.ByteOrder, uint16(f.ELFHeader32.Shentsize))
		binary.Write(w, f.ByteOrder, uint16(len(f.Sections)))
		binary.Write(w, f.ByteOrder, uint16(f.ELFHeader32.Shstrndx))
		bytesWritten += 28
	case ELFCLASS64:
		binary.Write(w, f.ByteOrder, uint64(f.Entry))
		binary.Write(w, f.ByteOrder, uint64(f.ELFHeader64.Phoff))
		binary.Write(w, f.ByteOrder, int64(f.ELFHeader64.Shoff))
		binary.Write(w, f.ByteOrder, uint32(f.ELFHeader64.Flags))
		binary.Write(w, f.ByteOrder, uint16(f.ELFHeader64.Ehsize))
		binary.Write(w, f.ByteOrder, uint16(f.ELFHeader64.Phentsize))
		binary.Write(w, f.ByteOrder, uint16(len(f.Progs)))
		binary.Write(w, f.ByteOrder, uint16(f.ELFHeader64.Shentsize))
		binary.Write(w, f.ByteOrder, uint16(len(f.Sections)))
		binary.Write(w, f.ByteOrder, uint16(f.ELFHeader64.Shstrndx))
		bytesWritten += 40
	}

	// Program Header
	for _, p := range f.Progs {
		// Type (segment)
		binary.Write(w, f.ByteOrder, uint32(p.Type))
		bytesWritten += 4

		switch f.Class {
		case ELFCLASS32:
			binary.Write(w, f.ByteOrder, uint32(p.Off))
			binary.Write(w, f.ByteOrder, uint32(p.Vaddr))
			binary.Write(w, f.ByteOrder, uint32(p.Paddr))
			binary.Write(w, f.ByteOrder, uint32(p.Filesz))
			binary.Write(w, f.ByteOrder, uint32(p.Memsz))
			binary.Write(w, f.ByteOrder, uint32(p.Flags))
			binary.Write(w, f.ByteOrder, uint32(p.Align))
			bytesWritten += 28
		case ELFCLASS64:
			binary.Write(w, f.ByteOrder, uint32(p.Flags))
			binary.Write(w, f.ByteOrder, uint64(p.Off))
			binary.Write(w, f.ByteOrder, uint64(p.Vaddr))
			binary.Write(w, f.ByteOrder, uint64(p.Paddr))
			binary.Write(w, f.ByteOrder, uint64(p.Filesz))
			binary.Write(w, f.ByteOrder, uint64(p.Memsz))
			binary.Write(w, f.ByteOrder, uint64(p.Align))
			bytesWritten += 52
		}
	}

	for _, s := range f.Sections {

		//log.Printf("Writing section: %s type: %+v\n", s.Name, s.Type)
		//log.Printf("written: %x offset: %x\n", bytesWritten, s.Offset)

		if s.Type == SHT_NULL || s.Type == SHT_NOBITS || s.FileSize == 0 {
			continue
		}

		if bytesWritten > s.Offset {
			log.Printf("Overlapping Sections in Generated Elf: %+v\n", s.Name)
			continue
		}
		if s.Offset != 0 && bytesWritten < s.Offset {
			pad := make([]byte, s.Offset-bytesWritten)
			w.Write(pad)
			//log.Printf("Padding before section %s at %x: length:%x to:%x\n", s.Name, bytesWritten, len(pad), s.Offset)
			bytesWritten += uint64(len(pad))
		}

		slen := 0
		switch s.Type {
		case SHT_DYNAMIC:
			for tag, value := range f.DynamicTags {
				//log.Printf("writing %d (%x) -> %d (%x)\n", tag, tag, value, value)
				switch f.Class {
				case ELFCLASS32:
					binary.Write(w, f.ByteOrder, uint32(tag))
					binary.Write(w, f.ByteOrder, uint32(value))
					bytesWritten += 8
				case ELFCLASS64:
					binary.Write(w, f.ByteOrder, uint64(tag))
					binary.Write(w, f.ByteOrder, uint64(value))
					bytesWritten += 16
				}
			}
		default:
			section, err := ioutil.ReadAll(s.Open())
			if err != nil {
				return nil, err
			}
			binary.Write(w, f.ByteOrder, section)
			slen = len(section)
			//log.Printf("Wrote %s section at %x, length %x\n", s.Name, bytesWritten, slen)
			bytesWritten += uint64(slen)
		}

		if s.Type == SHT_PROGBITS && len(f.Injection) > 0 && s.Size-uint64(slen) >= uint64(len(f.Injection)) {
			binary.Write(w, f.ByteOrder, f.Injection)
			bytesWritten += uint64(len(f.Injection))
		}
		w.Flush()
	}

	// Pad to Section Header Table
	switch f.Class {
	case ELFCLASS32:
		if bytesWritten < uint64(f.ELFHeader32.Shoff) {
			pad := make([]byte, uint64(f.ELFHeader32.Shoff)-bytesWritten)
			w.Write(pad)
			//log.Printf("Padding before SHT at %x: length:%x to:%x\n", bytesWritten, len(pad), f.ELFHeader32.Shoff)
			bytesWritten += uint64(len(pad))
		}
	case ELFCLASS64:
		if bytesWritten < uint64(f.ELFHeader64.Shoff) {
			pad := make([]byte, uint64(f.ELFHeader64.Shoff)-bytesWritten)
			w.Write(pad)
			//log.Printf("Padding before SHT at %x: length:%x to:%x\n", bytesWritten, len(pad), f.ELFHeader32.Shoff)
			bytesWritten += uint64(len(pad))
		}
	}

	// Write Section Header Table
	for _, s := range f.Sections {
		switch f.Class {
		case ELFCLASS32:
			binary.Write(w, f.ByteOrder, &Section32{
				Name:      uint32(s.Index),
				Type:      uint32(s.Type),
				Flags:     uint32(s.Flags),
				Addr:      uint32(s.Addr),
				Off:       uint32(s.Offset),
				Size:      uint32(s.Size),
				Link:      s.Link,
				Info:      s.Info,
				Addralign: uint32(s.Addralign),
				Entsize:   uint32(s.Entsize),
			})
		case ELFCLASS64:
			binary.Write(w, f.ByteOrder, &Section64{
				Name:      uint32(s.Index),
				Type:      uint32(s.Type),
				Flags:     uint64(s.Flags),
				Addr:      s.Addr,
				Off:       s.Offset,
				Size:      s.Size,
				Link:      s.Link,
				Info:      s.Info,
				Addralign: s.Addralign,
				Entsize:   s.Entsize,
			})
		}
	}

	// TODO: Do I have a PT_NOTE segment to add at the end?

	if len(f.InjectionEOF) > 0 {
		binary.Write(w, f.ByteOrder, f.InjectionEOF)
		bytesWritten += uint64(len(f.InjectionEOF))
	}

	w.Flush()

	return buf.Bytes(), nil
}

