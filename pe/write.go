package pe

import (
	"bufio"
	"encoding/binary"
	"errors"
	"os"
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
	bytesWritten += uint64(binary.Size(peFile.FileHeader) + len(peMagic))

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
	sectionHeaders := make([]SectionHeader32, len(peFile.Sections))
	for idx, section := range peFile.Sections {
		// write section header
		sectionHeader := SectionHeader32 {
			Name:				  section.OriginalName,
			VirtualSize:		  section.VirtualSize,
			VirtualAddress:       section.VirtualAddress,
			SizeOfRawData:        section.Size,
			PointerToRawData:     section.Offset,
			PointerToRelocations: section.PointerToRelocations,
			PointerToLineNumbers: section.PointerToLineNumbers,
			NumberOfRelocations:  section.NumberOfRelocations,
			NumberOfLineNumbers:  section.NumberOfLineNumbers,
			Characteristics:      section.Characteristics,
		}
		sectionHeaders[idx] = sectionHeader

		binary.Write(w, binary.LittleEndian, sectionHeader)
		bytesWritten += uint64(binary.Size(sectionHeader))
	}

	w.Flush()

	// write sections' data
	for idx, sectionHeader := range sectionHeaders {
		sectionData, err := peFile.Sections[idx].Data()
		if err != nil {
			return err
		}

		// pad section if there is a gap between PointerToRawData end of last section
		if sectionHeader.PointerToRawData != uint32(bytesWritten) {
			paddingSize := sectionHeader.PointerToRawData - uint32(bytesWritten)
			padding := make([]byte, paddingSize, paddingSize)
			sectionData = append(padding, sectionData...)
		}

		// pad section if VirtualSize is greater than SizeOfRawData
		/*if sectionHeader.VirtualSize > sectionHeader.SizeOfRawData {
			paddingSize := sectionHeader.VirtualSize - sectionHeader.SizeOfRawData
			padding := make([]byte, paddingSize, paddingSize)
			sectionData = append(padding, sectionData...)
		}*/

		binary.Write(w, binary.LittleEndian, sectionData)
		bytesWritten += uint64(len(sectionData))

		w.Flush()
	}

	/*
	for i := range f.Sections {
		var err error
		f.Sections[i].Relocs, err = readRelocs(&f.Sections[i].SectionHeader, sr)
		if err != nil {
			return nil, err
		}
	}
	*/

	// write symbols
	binary.Write(w, binary.LittleEndian, peFile.COFFSymbols)
	bytesWritten += uint64(binary.Size(peFile.COFFSymbols))

	// write the string table
	binary.Write(w, binary.LittleEndian, peFile.StringTable)
	bytesWritten += uint64(binary.Size(peFile.StringTable))

	w.Flush()

	return nil
}