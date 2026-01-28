package pe

import (
	"fmt"
)

// AddBaseRelocation appends a relocation block to the base relocation table.
func (f *File) AddBaseRelocation(block RelocationTableEntry) {
	if f.BaseRelocationTable == nil {
		entries := []RelocationTableEntry{}
		f.BaseRelocationTable = &entries
	}
	*f.BaseRelocationTable = append(*f.BaseRelocationTable, block)
}

// ReplaceBaseRelocations replaces the base relocation table.
func (f *File) ReplaceBaseRelocations(blocks []RelocationTableEntry) {
	if f.BaseRelocationTable == nil {
		entries := []RelocationTableEntry{}
		f.BaseRelocationTable = &entries
	}
	*f.BaseRelocationTable = append((*f.BaseRelocationTable)[:0], blocks...)
}

// RemoveBaseRelocations clears all base relocation entries.
func (f *File) RemoveBaseRelocations() {
	if f.BaseRelocationTable == nil {
		entries := []RelocationTableEntry{}
		f.BaseRelocationTable = &entries
	}
	*f.BaseRelocationTable = (*f.BaseRelocationTable)[:0]
}

// AddBaseReloc adds a single base relocation to the block for the containing page.
func (f *File) AddBaseReloc(rva uint32, typ byte) {
	page := rva &^ 0x0fff
	offset := uint16(rva & 0x0fff)
	item := BlockItem{Type: typ, Offset: offset}

	if f.BaseRelocationTable == nil {
		entries := []RelocationTableEntry{}
		f.BaseRelocationTable = &entries
	}
	for i := range *f.BaseRelocationTable {
		if (*f.BaseRelocationTable)[i].VirtualAddress == page {
			(*f.BaseRelocationTable)[i].BlockItems = append((*f.BaseRelocationTable)[i].BlockItems, item)
			return
		}
	}
	*f.BaseRelocationTable = append(*f.BaseRelocationTable, RelocationTableEntry{
		RelocationBlock: RelocationBlock{VirtualAddress: page},
		BlockItems:      []BlockItem{item},
	})
}

// AddSectionRelocation appends a COFF relocation to a section.
func (f *File) AddSectionRelocation(sectionName string, rel Reloc) error {
	section := f.Section(sectionName)
	if section == nil {
		return fmt.Errorf("section %q not found", sectionName)
	}
	section.Relocs = append(section.Relocs, rel)
	return nil
}

// AddSectionRelocationForSymbol appends a COFF relocation using a symbol name lookup.
func (f *File) AddSectionRelocationForSymbol(sectionName string, symbolName string, rel Reloc) error {
	index, err := f.SymbolIndexByName(symbolName)
	if err != nil {
		return err
	}
	rel.SymbolTableIndex = index
	return f.AddSectionRelocation(sectionName, rel)
}

// SymbolIndexByName returns the COFF symbol table index for the given name.
func (f *File) SymbolIndexByName(symbolName string) (uint32, error) {
	if len(f.COFFSymbols) == 0 {
		return 0, fmt.Errorf("no COFF symbols available")
	}
	for i := range f.COFFSymbols {
		name, err := f.COFFSymbols[i].FullName(f.StringTable)
		if err != nil {
			return 0, err
		}
		if name == symbolName {
			return uint32(i), nil
		}
	}
	return 0, fmt.Errorf("symbol %q not found", symbolName)
}

// ReplaceSectionRelocations replaces COFF relocations for a section.
func (f *File) ReplaceSectionRelocations(sectionName string, rels []Reloc) error {
	section := f.Section(sectionName)
	if section == nil {
		return fmt.Errorf("section %q not found", sectionName)
	}
	section.Relocs = append(section.Relocs[:0], rels...)
	return nil
}

// RemoveSectionRelocations clears COFF relocations for a section.
func (f *File) RemoveSectionRelocations(sectionName string) error {
	section := f.Section(sectionName)
	if section == nil {
		return fmt.Errorf("section %q not found", sectionName)
	}
	section.Relocs = section.Relocs[:0]
	return nil
}
