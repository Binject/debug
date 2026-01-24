package pe

import (
	"bytes"
	"encoding/binary"
	"errors"
)

func (f *File) prepareRelocationLayout() ([]byte, uint32, error) {
	sectionAlign, fileAlign, dataDir, sizeOfImage, sizeOfHeaders, err := f.optionalHeaderInfo()
	if err != nil {
		return nil, 0, err
	}

	relocData := f.buildBaseRelocationData()
	relocSection := f.Section(".reloc")

	maxRawEnd, maxVirtualEnd := f.maxSectionEnds(relocSection, sectionAlign)
	if len(relocData) > 0 {
		if relocSection == nil {
			relocSection = &Section{
				SectionHeader: SectionHeader{
					Name:             ".reloc",
					Characteristics:  IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE,
					PointerToLineNumbers: 0,
					NumberOfLineNumbers:  0,
				},
			}
			copy(relocSection.OriginalName[:], []byte(".reloc"))
			f.Sections = append(f.Sections, relocSection)
			f.FileHeader.NumberOfSections = uint16(len(f.Sections))
		}
		relocSection.VirtualSize = uint32(len(relocData))
		relocSection.Size = align32(uint32(len(relocData)), fileAlign)
		relocSection.PointerToRelocations = 0
		relocSection.NumberOfRelocations = 0
		relocSection.Offset = align32(maxRawEnd, fileAlign)
		relocSection.VirtualAddress = align32(maxVirtualEnd, sectionAlign)
		padded := make([]byte, relocSection.Size)
		copy(padded, relocData)
		relocSection.Replace(bytes.NewReader(padded), int64(len(padded)))
		maxRawEnd = relocSection.Offset + relocSection.Size
		maxVirtualEnd = relocSection.VirtualAddress + align32(relocSection.VirtualSize, sectionAlign)

		dataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC] = DataDirectory{
			VirtualAddress: relocSection.VirtualAddress,
			Size:           uint32(len(relocData)),
		}
		f.FileHeader.Characteristics &^= IMAGE_FILE_RELOCS_STRIPPED
	} else {
		dataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC] = DataDirectory{}
	}

	*sizeOfImage = align32(maxVirtualEnd, sectionAlign)
	*sizeOfHeaders = align32(f.headersSize(), fileAlign)

	coffRelocData, coffRelocStart, err := f.buildCOFFRelocationData(maxRawEnd, fileAlign)
	if err != nil {
		return nil, 0, err
	}
	if len(f.COFFSymbols) > 0 {
		f.FileHeader.PointerToSymbolTable = align32(coffRelocStart+uint32(len(coffRelocData)), 4)
	} else {
		f.FileHeader.PointerToSymbolTable = 0
	}

	return coffRelocData, coffRelocStart, nil
}

func (f *File) optionalHeaderInfo() (uint32, uint32, *[16]DataDirectory, *uint32, *uint32, error) {
	switch hdr := f.OptionalHeader.(type) {
	case *OptionalHeader32:
		return hdr.SectionAlignment, hdr.FileAlignment, &hdr.DataDirectory, &hdr.SizeOfImage, &hdr.SizeOfHeaders, nil
	case *OptionalHeader64:
		return hdr.SectionAlignment, hdr.FileAlignment, &hdr.DataDirectory, &hdr.SizeOfImage, &hdr.SizeOfHeaders, nil
	default:
		return 0, 0, nil, nil, nil, errors.New("optional header not available")
	}
}

func (f *File) maxSectionEnds(skip *Section, sectionAlign uint32) (uint32, uint32) {
	var maxRawEnd uint32
	var maxVirtualEnd uint32
	for _, s := range f.Sections {
		if s == skip {
			continue
		}
		rawEnd := s.Offset + s.Size
		if rawEnd > maxRawEnd {
			maxRawEnd = rawEnd
		}
		virtualSize := s.VirtualSize
		if virtualSize == 0 {
			virtualSize = s.Size
		}
		virtualEnd := s.VirtualAddress + align32(virtualSize, sectionAlign)
		if virtualEnd > maxVirtualEnd {
			maxVirtualEnd = virtualEnd
		}
	}
	return maxRawEnd, maxVirtualEnd
}

func (f *File) buildBaseRelocationData() []byte {
	if f.BaseRelocationTable == nil {
		return nil
	}
	var buf bytes.Buffer
	for _, entry := range *f.BaseRelocationTable {
		items := entry.BlockItems
		if len(items)%2 != 0 {
			items = append(items, BlockItem{Type: IMAGE_REL_BASED_ABSOLUTE})
		}
		sizeOfBlock := uint32(8 + len(items)*2)
		block := RelocationBlock{
			VirtualAddress: entry.VirtualAddress,
			SizeOfBlock:    sizeOfBlock,
		}
		binary.Write(&buf, binary.LittleEndian, block)
		for _, item := range items {
			val := (uint16(item.Type) << 12) | (item.Offset & 0x0fff)
			binary.Write(&buf, binary.LittleEndian, val)
		}
	}
	return buf.Bytes()
}

func (f *File) buildCOFFRelocationData(start uint32, fileAlign uint32) ([]byte, uint32, error) {
	if start == 0 {
		start = fileAlign
	}
	offset := align32(start, fileAlign)
	buf := bytes.NewBuffer(nil)

	for _, s := range f.Sections {
		if len(s.Relocs) == 0 {
			s.PointerToRelocations = 0
			s.NumberOfRelocations = 0
			continue
		}
		if len(s.Relocs) > int(^uint16(0)) {
			return nil, 0, errors.New("too many COFF relocations for section")
		}
		offset = align32(offset, 4)
		s.PointerToRelocations = offset
		s.NumberOfRelocations = uint16(len(s.Relocs))

		pad := int(offset - start - uint32(buf.Len()))
		if pad > 0 {
			buf.Write(make([]byte, pad))
		}
		for _, rel := range s.Relocs {
			if err := binary.Write(buf, binary.LittleEndian, rel); err != nil {
				return nil, 0, err
			}
		}
		offset += uint32(len(s.Relocs)) * uint32(binary.Size(Reloc{}))
	}

	return buf.Bytes(), start, nil
}

func (f *File) headersSize() uint32 {
	size := uint32(f.DosHeader.AddressOfNewExeHeader)
	size += 4 // PE signature
	size += uint32(binary.Size(f.FileHeader))
	size += uint32(f.FileHeader.SizeOfOptionalHeader)
	size += uint32(len(f.Sections)) * uint32(binary.Size(SectionHeader32{}))
	return size
}

func align32(value, align uint32) uint32 {
	if align == 0 {
		return value
	}
	rem := value % align
	if rem == 0 {
		return value
	}
	return value + (align - rem)
}
