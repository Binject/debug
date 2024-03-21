package elf

// ExportedSymbols returns the exported and defined dynamic symbol table for f.
//
// For compatibility with [File.DynamicSymbols], [File.ExportedSymbols] returns the same
// slice of exported [Symbol]s, with the difference being that [Symbol.Section] != [SHN_UNDEF].
func (f *File) ExportedSymbols() ([]Symbol, error) {

	exported := make([]Symbol, 0)
	symbols, err := f.DynamicSymbols()
	if err != nil {
		return nil, err
	}
	for _, s := range symbols {
		if s.Section != SHN_UNDEF {
			exported = append(exported, s)
		}
	}

	return exported, nil
}
