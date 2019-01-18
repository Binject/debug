package pe

import (
	"bufio"
	"encoding/binary"
	"errors"
	//"io/ioutil"
	"log"
	"os"
	//"sort"
)

func (peFile *File) Write(destFile string) error {

	bytesWritten := uint64(0)
	f, err := os.Create(destFile)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)

	// write DOS header and stub
	binary.Write(w, binary.LittleEndian, peFile.DosHeader)
	bytesWritten += uint64(binary.Size(peFile.DosHeader))
	binary.Write(w, binary.LittleEndian, peFile.DosStub)
	bytesWritten += uint64(binary.Size(peFile.DosStub))

	// write PE header
	peMagic := []byte{'P', 'E', 0x00, 0x00}
	binary.Write(w, binary.LittleEndian, peMagic)
	binary.Write(w, binary.LittleEndian, peFile.FileHeader)
	bytesWritten += uint64(binary.Size(peFile.FileHeader))

	switch peFile.FileHeader.Machine {
	case IMAGE_FILE_MACHINE_I386:
		optionalHeader := peFile.OptionalHeader.(*OptionalHeader32)
		binary.Write(w, binary.LittleEndian, optionalHeader)
		bytesWritten += uint64(binary.Size(optionalHeader))
	case IMAGE_FILE_MACHINE_AMD64:
		optionalHeader := peFile.OptionalHeader.(*OptionalHeader64)
		binary.Write(w, binary.LittleEndian, optionalHeader)
		bytesWritten += uint64(binary.Size(optionalHeader))
	default:
		return errors.New("architecture not supported")
	}

	// write section headers
	for _, section := range peFile.Sections {
		log.Println(section.SectionHeader)
		binary.Write(w, binary.LittleEndian, section.SectionHeader)
		bytesWritten += uint64(binary.Size(section.SectionHeader))
	}



	/*

	// Process sections.
	f.Sections = make([]*Section, f.FileHeader.NumberOfSections)
	for i := 0; i < int(f.FileHeader.NumberOfSections); i++ {
		sh := new(SectionHeader32)
		if err := binary.Read(sr, binary.LittleEndian, sh); err != nil {
			return nil, err
		}
		name, err := sh.fullName(f.StringTable)
		if err != nil {
			return nil, err
		}
		s := new(Section)
		s.SectionHeader = SectionHeader{
			Name:                 name,
			VirtualSize:          sh.VirtualSize,
			VirtualAddress:       sh.VirtualAddress,
			Size:                 sh.SizeOfRawData,
			Offset:               sh.PointerToRawData,
			PointerToRelocations: sh.PointerToRelocations,
			PointerToLineNumbers: sh.PointerToLineNumbers,
			NumberOfRelocations:  sh.NumberOfRelocations,
			NumberOfLineNumbers:  sh.NumberOfLineNumbers,
			Characteristics:      sh.Characteristics,
		}
		r2 := r
		if sh.PointerToRawData == 0 { // .bss must have all 0s
			r2 = zeroReaderAt{}
		}
		s.sr = io.NewSectionReader(r2, int64(s.SectionHeader.Offset), int64(s.SectionHeader.Size))
		s.ReaderAt = s.sr
		f.Sections[i] = s
	}
	for i := range f.Sections {
		var err error
		f.Sections[i].Relocs, err = readRelocs(&f.Sections[i].SectionHeader, sr)
		if err != nil {
			return nil, err
		}
	}

	// Read symbol table.
	f.COFFSymbols, err = readCOFFSymbols(&f.FileHeader, sr)
	if err != nil {
		return nil, err
	}
	f.Symbols, err = removeAuxSymbols(f.COFFSymbols, f.StringTable)
	if err != nil {
		return nil, err
	}

	// Read string table.
	f.StringTable, err = readStringTable(&f.FileHeader, sr)
	if err != nil {
		return nil, err
	}

	return f, nil
	*/

	w.Flush()

	return nil
}