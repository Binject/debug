package elf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// AddRelocation appends a single relocation entry to the target section.
func (f *File) AddRelocation(target *Section, rel interface{}) error {
	return f.AddRelocations(target, rel)
}

// AddRelocations appends relocation entries to the target section.
func (f *File) AddRelocations(target *Section, rels interface{}) error {
	return f.addRelocations(target, rels, false, nil)
}

// ReplaceRelocations replaces relocation entries for the target section.
func (f *File) ReplaceRelocations(target *Section, rels interface{}) error {
	return f.addRelocations(target, rels, true, nil)
}

// RemoveRelocations clears relocation entries for the target section.
func (f *File) RemoveRelocations(target *Section) error {
	if target == nil {
		return errors.New("target section is nil")
	}
	targetIndex, ok := f.sectionIndex(target)
	if !ok {
		return errors.New("target section not found in file")
	}
	relocSecRel, _ := f.relocationSection(targetIndex, SHT_REL)
	relocSecRela, _ := f.relocationSection(targetIndex, SHT_RELA)
	if relocSecRel == nil && relocSecRela == nil {
		return nil
	}
	if relocSecRel != nil {
		relocSecRel.Replace(bytes.NewReader(nil), 0)
	}
	if relocSecRela != nil {
		relocSecRela.Replace(bytes.NewReader(nil), 0)
	}
	f.updateDynamicRelocTags()
	return nil
}

// AddRelocationsToRelocSection appends relocation entries to a specific relocation section
// (e.g. ".rela.dyn" or ".rel.plt").
func (f *File) AddRelocationsToRelocSection(sectionName string, rels interface{}) error {
	relocSec := f.Section(sectionName)
	if relocSec == nil {
		return fmt.Errorf("relocation section %q not found", sectionName)
	}
	if relocSec.Type != SHT_REL && relocSec.Type != SHT_RELA {
		return fmt.Errorf("section %q is not a relocation section", sectionName)
	}

	data, relType, entSize, err := encodeRelocations(f.ByteOrder, rels)
	if err != nil {
		return err
	}
	if relType != relocSec.Type {
		return fmt.Errorf("relocation type mismatch for %q", sectionName)
	}

	var existing []byte
	if relocSec.sr != nil {
		existing, err = relocSec.Data()
		if err != nil {
			return err
		}
	}
	relocSec.Addralign = relocationAlign(f.Class)
	relocSec.Entsize = entSize
	relocSec.Replace(bytes.NewReader(append(existing, data...)), int64(len(existing)+len(data)))

	if modified, err := f.ensureSectionName(relocSec); err != nil {
		return err
	} else {
		if err := f.relayoutRelocationSections(modified); err != nil {
			return err
		}
	}
	if err := f.relayoutAllocRelocationSection(relocSec); err != nil {
		return err
	}
	f.updateDynamicRelocTags()
	return nil
}

// RemoveRelocationsFromRelocSection clears relocation entries for the named relocation section.
func (f *File) RemoveRelocationsFromRelocSection(sectionName string) error {
	relocSec := f.Section(sectionName)
	if relocSec == nil {
		return fmt.Errorf("relocation section %q not found", sectionName)
	}
	if relocSec.Type != SHT_REL && relocSec.Type != SHT_RELA {
		return fmt.Errorf("section %q is not a relocation section", sectionName)
	}
	relocSec.Replace(bytes.NewReader(nil), 0)
	f.updateDynamicRelocTags()
	return nil
}

// AddRelocationForSymbol builds and adds a relocation for the named symbol.
// If addend is nil, a REL entry is created. Otherwise a RELA entry is used.
func (f *File) AddRelocationForSymbol(sectionName, symbolName string, offset uint64, rType uint32, addend *int64) error {
	target := f.Section(sectionName)
	if target == nil {
		return fmt.Errorf("section %q not found", sectionName)
	}
	symIndex, symtabIndex, err := f.symbolIndexByName(symbolName)
	if err != nil {
		return err
	}
	return f.addRelocationEntry(target, symIndex, symtabIndex, offset, rType, addend)
}

// AddRelocationForAddr builds and adds a relocation that references no symbol.
// If addend is nil, a REL entry is created. Otherwise a RELA entry is used.
func (f *File) AddRelocationForAddr(sectionName string, offset uint64, rType uint32, addend *int64) error {
	target := f.Section(sectionName)
	if target == nil {
		return fmt.Errorf("section %q not found", sectionName)
	}
	return f.addRelocationEntry(target, 0, -1, offset, rType, addend)
}

func (f *File) addRelocationEntry(target *Section, symIndex uint32, symtabIndex int, offset uint64, rType uint32, addend *int64) error {
	switch f.Class {
	case ELFCLASS32:
		if offset > uint64(^uint32(0)) {
			return fmt.Errorf("relocation offset %#x overflows 32-bit", offset)
		}
		if addend == nil {
			rel := Rel32{Off: uint32(offset), Info: R_INFO32(symIndex, rType)}
			return f.addRelocations(target, []Rel32{rel}, false, pickLink(symtabIndex))
		}
		if *addend > maxInt32 || *addend < minInt32 {
			return fmt.Errorf("addend %d overflows 32-bit", *addend)
		}
		rel := Rela32{Off: uint32(offset), Info: R_INFO32(symIndex, rType), Addend: int32(*addend)}
		return f.addRelocations(target, []Rela32{rel}, false, pickLink(symtabIndex))
	case ELFCLASS64:
		if addend == nil {
			rel := Rel64{Off: offset, Info: R_INFO(symIndex, rType)}
			return f.addRelocations(target, []Rel64{rel}, false, pickLink(symtabIndex))
		}
		rel := Rela64{Off: offset, Info: R_INFO(symIndex, rType), Addend: *addend}
		return f.addRelocations(target, []Rela64{rel}, false, pickLink(symtabIndex))
	default:
		return errors.New("unsupported ELF class")
	}
}

const (
	minInt32 = -1 << 31
	maxInt32 = 1<<31 - 1
)

func pickLink(index int) *int {
	if index < 0 {
		return nil
	}
	return &index
}

func (f *File) addRelocations(target *Section, rels interface{}, replace bool, linkOverride *int) error {
	if target == nil {
		return errors.New("target section is nil")
	}
	targetIndex, ok := f.sectionIndex(target)
	if !ok {
		return errors.New("target section not found in file")
	}

	data, relType, entSize, err := encodeRelocations(f.ByteOrder, rels)
	if err != nil {
		return err
	}

	relocSec, _ := f.relocationSection(targetIndex, relType)
	newSection := false
	if relocSec == nil {
		relocSec = &Section{
			SectionHeader: SectionHeader{
				Name:      relocationSectionName(target.Name, relType),
				Type:      relType,
				Flags:     0,
				Addr:      0,
				Offset:    0,
				Size:      0,
				Link:      0,
				Info:      uint32(targetIndex),
				Addralign: relocationAlign(f.Class),
				Entsize:   entSize,
			},
		}
		newSection = true
	}

	linkIndex := relocSec.Link
	if linkOverride != nil {
		linkIndex = uint32(*linkOverride)
	}
	if linkIndex == 0 {
		defaultLink, err := f.defaultSymtabIndex()
		if err != nil {
			return err
		}
		linkIndex = uint32(defaultLink)
	}
	if relocSec.Link != 0 && relocSec.Link != linkIndex {
		return fmt.Errorf("relocation section links to symtab %d, want %d", relocSec.Link, linkIndex)
	}
	relocSec.Link = linkIndex
	relocSec.Info = uint32(targetIndex)
	relocSec.Addralign = relocationAlign(f.Class)
	relocSec.Entsize = entSize

	oldFileSize := relocSec.FileSize
	if !replace {
		var existing []byte
		if relocSec.sr != nil {
			var err error
			existing, err = relocSec.Data()
			if err != nil {
				return err
			}
		}
		data = append(existing, data...)
	}
	relocSec.Replace(bytes.NewReader(data), int64(len(data)))

	shstrModified := false
	if modified, err := f.ensureSectionName(relocSec); err != nil {
		return err
	} else if modified {
		shstrModified = true
	}

	if newSection {
		f.Sections = append(f.Sections, relocSec)
		shstrModified = true
	}
	if err := f.relayoutRelocationSections(shstrModified); err != nil {
		return err
	}
	if relocSec.Flags&SHF_ALLOC != 0 && relocSec.FileSize != oldFileSize {
		if err := f.relayoutAllocRelocationSection(relocSec); err != nil {
			return err
		}
	}
	f.updateDynamicRelocTags()
	return nil
}

func encodeRelocations(order binary.ByteOrder, rels interface{}) ([]byte, SectionType, uint64, error) {
	buf := bytes.NewBuffer(nil)
	switch v := rels.(type) {
	case Rel32:
		if err := binary.Write(buf, order, v); err != nil {
			return nil, 0, 0, err
		}
		return buf.Bytes(), SHT_REL, uint64(binary.Size(Rel32{})), nil
	case []Rel32:
		for _, rel := range v {
			if err := binary.Write(buf, order, rel); err != nil {
				return nil, 0, 0, err
			}
		}
		return buf.Bytes(), SHT_REL, uint64(binary.Size(Rel32{})), nil
	case Rela32:
		if err := binary.Write(buf, order, v); err != nil {
			return nil, 0, 0, err
		}
		return buf.Bytes(), SHT_RELA, uint64(binary.Size(Rela32{})), nil
	case []Rela32:
		for _, rel := range v {
			if err := binary.Write(buf, order, rel); err != nil {
				return nil, 0, 0, err
			}
		}
		return buf.Bytes(), SHT_RELA, uint64(binary.Size(Rela32{})), nil
	case Rel64:
		if err := binary.Write(buf, order, v); err != nil {
			return nil, 0, 0, err
		}
		return buf.Bytes(), SHT_REL, uint64(binary.Size(Rel64{})), nil
	case []Rel64:
		for _, rel := range v {
			if err := binary.Write(buf, order, rel); err != nil {
				return nil, 0, 0, err
			}
		}
		return buf.Bytes(), SHT_REL, uint64(binary.Size(Rel64{})), nil
	case Rela64:
		if err := binary.Write(buf, order, v); err != nil {
			return nil, 0, 0, err
		}
		return buf.Bytes(), SHT_RELA, uint64(binary.Size(Rela64{})), nil
	case []Rela64:
		for _, rel := range v {
			if err := binary.Write(buf, order, rel); err != nil {
				return nil, 0, 0, err
			}
		}
		return buf.Bytes(), SHT_RELA, uint64(binary.Size(Rela64{})), nil
	default:
		return nil, 0, 0, fmt.Errorf("unsupported relocation type %T", rels)
	}
}

func relocationSectionName(targetName string, relType SectionType) string {
	if relType == SHT_RELA {
		return ".rela" + targetName
	}
	return ".rel" + targetName
}

func relocationAlign(class Class) uint64 {
	if class == ELFCLASS64 {
		return 8
	}
	return 4
}

func (f *File) relocationSection(targetIndex int, relType SectionType) (*Section, int) {
	for i, s := range f.Sections {
		if s.Type != relType {
			continue
		}
		if int(s.Info) == targetIndex {
			return s, i
		}
	}
	return nil, -1
}

func (f *File) sectionIndex(target *Section) (int, bool) {
	for i, s := range f.Sections {
		if s == target {
			return i, true
		}
	}
	return -1, false
}

func (f *File) defaultSymtabIndex() (int, error) {
	if idx, ok := f.sectionIndexByName(".symtab"); ok {
		return idx, nil
	}
	if idx, ok := f.sectionIndexByName(".dynsym"); ok {
		return idx, nil
	}
	return -1, errors.New("no symbol table section found")
}

func (f *File) sectionIndexByName(name string) (int, bool) {
	for i, s := range f.Sections {
		if s.Name == name {
			return i, true
		}
	}
	return -1, false
}

func (f *File) symbolIndexByName(name string) (uint32, int, error) {
	if symtabIndex, ok := f.sectionIndexByName(".symtab"); ok {
		syms, err := f.Symbols()
		if err == nil {
			for i, sym := range syms {
				if sym.Name == name {
					return uint32(i + 1), symtabIndex, nil
				}
			}
		} else if !errors.Is(err, ErrNoSymbols) {
			return 0, -1, err
		}
	}
	if dynsymIndex, ok := f.sectionIndexByName(".dynsym"); ok {
		syms, err := f.DynamicSymbols()
		if err == nil {
			for i, sym := range syms {
				if sym.Name == name {
					return uint32(i + 1), dynsymIndex, nil
				}
			}
		} else if !errors.Is(err, ErrNoSymbols) {
			return 0, -1, err
		}
	}
	return 0, -1, fmt.Errorf("symbol %q not found", name)
}

func (f *File) ensureSectionName(section *Section) (bool, error) {
	if section.Name == "" {
		return false, nil
	}
	if f.ShStrIndex < 0 || f.ShStrIndex >= len(f.Sections) {
		return false, errors.New("invalid shstrtab index")
	}
	shstr := f.Sections[f.ShStrIndex]
	data, err := shstr.Data()
	if err != nil && shstr.sr != nil {
		return false, err
	}
	nameBytes := append([]byte(section.Name), 0)
	if idx := bytes.Index(data, nameBytes); idx >= 0 {
		section.Shname = uint32(idx)
		return false, nil
	}
	section.Shname = uint32(len(data))
	newData := append(data, nameBytes...)
	shstr.Replace(bytes.NewReader(newData), int64(len(newData)))
	return true, nil
}

func (f *File) relayoutRelocationSections(shstrModified bool) error {
	var moved []*Section
	for _, s := range f.Sections {
		if s.Type == SHT_REL || s.Type == SHT_RELA {
			moved = append(moved, s)
		}
	}
	if shstrModified && f.ShStrIndex >= 0 && f.ShStrIndex < len(f.Sections) {
		moved = append(moved, f.Sections[f.ShStrIndex])
	}
	if len(moved) == 0 {
		return nil
	}

	moveSet := map[*Section]struct{}{}
	for _, s := range moved {
		if s.Flags&SHF_ALLOC != 0 {
			continue
		}
		moveSet[s] = struct{}{}
	}

	var maxEnd uint64
	for _, s := range f.Sections {
		if _, ok := moveSet[s]; ok {
			continue
		}
		if s.Type == SHT_NOBITS || s.FileSize == 0 {
			continue
		}
		end := s.Offset + s.FileSize
		if end > maxEnd {
			maxEnd = end
		}
	}

	offset := maxEnd
	for _, s := range moved {
		if s.Flags&SHF_ALLOC != 0 {
			continue
		}
		align := s.Addralign
		if align == 0 {
			align = 1
		}
		offset = alignUp(offset, align)
		s.Offset = offset
		offset += s.FileSize
	}

	shtAlign := uint64(4)
	if f.Class == ELFCLASS64 {
		shtAlign = 8
	}
	f.SHTOffset = int64(alignUp(offset, shtAlign))
	return nil
}

func (f *File) relayoutAllocRelocationSection(section *Section) error {
	if section.Flags&SHF_ALLOC == 0 {
		return nil
	}
	var prog *Prog
	var progIndex int
	for i, p := range f.Progs {
		if p.Type != PT_LOAD {
			continue
		}
		if section.Addr >= p.Vaddr && section.Addr < p.Vaddr+p.Memsz {
			prog = p
			progIndex = i
			break
		}
	}
	if prog == nil {
		return fmt.Errorf("no PT_LOAD segment contains %q", section.Name)
	}

	var nextLoadOff uint64
	for i, p := range f.Progs {
		if p.Type != PT_LOAD || i == progIndex {
			continue
		}
		if p.Off > prog.Off && (nextLoadOff == 0 || p.Off < nextLoadOff) {
			nextLoadOff = p.Off
		}
	}

	align := section.Addralign
	if align == 0 {
		align = relocationAlign(f.Class)
	}
	newOff := alignUp(prog.Off+prog.Filesz, align)
	newEnd := newOff + section.FileSize
	if nextLoadOff != 0 && newEnd > nextLoadOff {
		return f.relayoutAllocRelocationSectionNewLoad(section)
	}
	newAddr := prog.Vaddr + (newOff - prog.Off)
	section.Offset = newOff
	section.Addr = newAddr
	if newEnd > prog.Off+prog.Filesz {
		delta := newEnd - (prog.Off + prog.Filesz)
		prog.Filesz += delta
		prog.Memsz += delta
	}
	if end := section.Offset + section.FileSize; int64(end) > f.SHTOffset {
		shtAlign := uint64(4)
		if f.Class == ELFCLASS64 {
			shtAlign = 8
		}
		f.SHTOffset = int64(alignUp(end, shtAlign))
	}
	return nil
}

func (f *File) relayoutAllocRelocationSectionNewLoad(section *Section) error {
	align := section.Addralign
	if align == 0 {
		align = relocationAlign(f.Class)
	}
	var lastLoad *Prog
	for _, p := range f.Progs {
		if p.Type != PT_LOAD {
			continue
		}
		if lastLoad == nil || p.Off > lastLoad.Off {
			lastLoad = p
		}
	}
	if lastLoad == nil {
		return fmt.Errorf("no PT_LOAD segments available")
	}
	baseOff := lastLoad.Off + lastLoad.Filesz
	fileEnd := f.maxFileEnd()
	if fileEnd > baseOff {
		baseOff = fileEnd
	}
	newOff := alignUp(baseOff, align)
	newAddr := lastLoad.Vaddr + (newOff - lastLoad.Off)
	section.Offset = newOff
	section.Addr = newAddr
	end := newOff + section.FileSize
	if end > lastLoad.Off+lastLoad.Filesz {
		delta := end - (lastLoad.Off + lastLoad.Filesz)
		lastLoad.Filesz += delta
		lastLoad.Memsz += delta
	}

	if end := section.Offset + section.FileSize; int64(end) > f.SHTOffset {
		shtAlign := uint64(4)
		if f.Class == ELFCLASS64 {
			shtAlign = 8
		}
		f.SHTOffset = int64(alignUp(end, shtAlign))
	}
	return nil
}

func (f *File) maxFileEnd() uint64 {
	var maxEnd uint64
	for _, s := range f.Sections {
		if s.Type == SHT_NOBITS || s.FileSize == 0 {
			continue
		}
		end := s.Offset + s.FileSize
		if end > maxEnd {
			maxEnd = end
		}
	}
	if f.SHTOffset > int64(maxEnd) {
		maxEnd = uint64(f.SHTOffset)
	}
	return maxEnd
}


func (f *File) updateDynamicRelocTags() {
	if len(f.DynTags) == 0 {
		return
	}
	for _, s := range f.Sections {
		if s.Flags&SHF_ALLOC == 0 || (s.Type != SHT_REL && s.Type != SHT_RELA) {
			continue
		}
		if s.Addr == 0 {
			continue
		}
		isPlt := strings.Contains(s.Name, ".plt")
		if s.Type == SHT_RELA {
			if isPlt {
				f.setDynTag(DT_JMPREL, s.Addr)
				f.setDynTag(DT_PLTRELSZ, s.Size)
				f.setDynTag(DT_PLTREL, uint64(DT_RELA))
			} else {
				f.setDynTag(DT_RELA, s.Addr)
				f.setDynTag(DT_RELASZ, s.Size)
				f.setDynTag(DT_RELAENT, s.Entsize)
			}
		} else {
			if isPlt {
				f.setDynTag(DT_JMPREL, s.Addr)
				f.setDynTag(DT_PLTRELSZ, s.Size)
				f.setDynTag(DT_PLTREL, uint64(DT_REL))
			} else {
				f.setDynTag(DT_REL, s.Addr)
				f.setDynTag(DT_RELSZ, s.Size)
				f.setDynTag(DT_RELENT, s.Entsize)
			}
		}
	}
}

func (f *File) setDynTag(tag DynTag, value uint64) {
	for i, entry := range f.DynTags {
		if entry.Tag == tag {
			f.DynTags[i].Value = value
			return
		}
	}
	f.DynTags = append(f.DynTags, DynTagValue{Tag: tag, Value: value})
}

func alignUp(value, align uint64) uint64 {
	if align == 0 {
		return value
	}
	rem := value % align
	if rem == 0 {
		return value
	}
	return value + (align - rem)
}
