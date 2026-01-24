package macho

import (
	"errors"
	"fmt"
)

// AddRelocation appends a relocation to the named section.
func (f *File) AddRelocation(sectionName string, rel Reloc) error {
	section := f.Section(sectionName)
	if section == nil {
		return fmt.Errorf("section %q not found", sectionName)
	}
	section.Relocs = append(section.Relocs, rel)
	return nil
}

// AddRelocations appends relocations to the named section.
func (f *File) AddRelocations(sectionName string, rels []Reloc) error {
	section := f.Section(sectionName)
	if section == nil {
		return fmt.Errorf("section %q not found", sectionName)
	}
	section.Relocs = append(section.Relocs, rels...)
	return nil
}

// ReplaceRelocations replaces relocations for the named section.
func (f *File) ReplaceRelocations(sectionName string, rels []Reloc) error {
	section := f.Section(sectionName)
	if section == nil {
		return fmt.Errorf("section %q not found", sectionName)
	}
	section.Relocs = append(section.Relocs[:0], rels...)
	return nil
}

// AddRelocationForSymbol creates a non-scattered relocation that references a symbol.
func (f *File) AddRelocationForSymbol(sectionName, symbolName string, addr uint32, relType uint8, length uint8, pcrel bool) error {
	if f.Symtab == nil {
		return errors.New("symbol table not available")
	}
	symIndex := -1
	for i, sym := range f.Symtab.Syms {
		if sym.Name == symbolName {
			symIndex = i
			break
		}
	}
	if symIndex < 0 {
		return fmt.Errorf("symbol %q not found", symbolName)
	}
	return f.AddRelocationForSymbolWithDylibOrdinal(sectionName, symbolName, addr, relType, length, pcrel, 0)
}

// AddRelocationForSymbolWithDylibOrdinal creates a relocation and records the dylib ordinal
// to use when generating bind info (0-15).
func (f *File) AddRelocationForSymbolWithDylibOrdinal(sectionName, symbolName string, addr uint32, relType uint8, length uint8, pcrel bool, dylibOrdinal uint8) error {
	if f.Symtab == nil {
		return errors.New("symbol table not available")
	}
	symIndex := -1
	for i, sym := range f.Symtab.Syms {
		if sym.Name == symbolName {
			symIndex = i
			break
		}
	}
	if symIndex < 0 {
		return fmt.Errorf("symbol %q not found", symbolName)
	}
	rel := Reloc{
		Addr:      addr,
		Value:     uint32(symIndex),
		Type:      relType,
		Len:       length,
		Pcrel:     pcrel,
		Extern:    true,
		Scattered: false,
	}
	if err := f.AddRelocation(sectionName, rel); err != nil {
		return err
	}
	return f.SetDylibOrdinalForSymbolIndex(uint32(symIndex), dylibOrdinal)
}

// SetDylibOrdinalForSymbol records a dylib ordinal for the named symbol.
func (f *File) SetDylibOrdinalForSymbol(symbolName string, ordinal uint8) error {
	if f.Symtab == nil {
		return errors.New("symbol table not available")
	}
	for i, sym := range f.Symtab.Syms {
		if sym.Name == symbolName {
			return f.SetDylibOrdinalForSymbolIndex(uint32(i), ordinal)
		}
	}
	return fmt.Errorf("symbol %q not found", symbolName)
}

// SetDylibOrdinalForSymbolIndex records a dylib ordinal for a symbol index.
func (f *File) SetDylibOrdinalForSymbolIndex(index uint32, ordinal uint8) error {
	if ordinal > 15 {
		return fmt.Errorf("dylib ordinal %d out of range", ordinal)
	}
	if f.dylibOrdinalBySymbol == nil {
		f.dylibOrdinalBySymbol = map[uint32]uint8{}
	}
	f.dylibOrdinalBySymbol[index] = ordinal
	return nil
}
