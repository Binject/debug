package macho

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

func (f *File) prepareRelocationData() ([]byte, uint64, error) {
	if err := f.prepareDyldInfoFromRelocs(); err != nil {
		return nil, 0, err
	}

	var relocCount int
	for _, s := range f.Sections {
		relocCount += len(s.Relocs)
	}
	if relocCount == 0 {
		for _, s := range f.Sections {
			s.Reloff = 0
			s.Nreloc = 0
		}
		return nil, 0, nil
	}

	start := alignUp64(f.maxFileOffset(), 4)
	offset := start
	buf := bytes.NewBuffer(nil)

	for _, s := range f.Sections {
		if len(s.Relocs) == 0 {
			s.Reloff = 0
			s.Nreloc = 0
			continue
		}
		offset = alignUp64(offset, 4)
		s.Reloff = uint32(offset)
		s.Nreloc = uint32(len(s.Relocs))

		pad := int(offset - start - uint64(buf.Len()))
		if pad > 0 {
			buf.Write(make([]byte, pad))
		}
		encoded, err := encodeRelocations(f.ByteOrder, s.Relocs)
		if err != nil {
			return nil, 0, err
		}
		buf.Write(encoded)
		offset += uint64(len(encoded))
	}

	return buf.Bytes(), start, nil
}

const (
	rebaseOpcodeDone                    = 0x00
	rebaseOpcodeSetTypeImm              = 0x10
	rebaseOpcodeSetSegmentAndOffsetULEB = 0x20
	rebaseOpcodeDoRebaseImmTimes        = 0x50
	rebaseTypePointer                   = 1

	bindOpcodeDone                    = 0x00
	bindOpcodeSetDylibOrdinalImm      = 0x10
	bindOpcodeSetSymbolTrailingFlags  = 0x40
	bindOpcodeSetTypeImm              = 0x50
	bindOpcodeSetSegmentAndOffsetULEB = 0x70
	bindOpcodeDoBind                  = 0x90
	bindTypePointer                   = 1
)

func (f *File) prepareDyldInfoFromRelocs() error {
	if f.DylinkInfo == nil {
		return nil
	}
	rebaseDat, bindDat, weakBindDat, lazyBindDat, err := f.encodeDyldInfoFromRelocs()
	if err != nil {
		return err
	}
	if len(rebaseDat) == 0 && len(bindDat) == 0 && len(weakBindDat) == 0 && len(lazyBindDat) == 0 {
		return nil
	}

	start := alignUp64(f.endOfSections(), 4)
	limit := f.dyldInfoEndLimit()
	total := uint64(len(rebaseDat) + len(bindDat) + len(weakBindDat) + len(lazyBindDat))
	if limit != 0 && start+total > limit {
		return fmt.Errorf("not enough room for dyld info")
	}

	offset := start
	f.DylinkInfo.RebaseDat = rebaseDat
	f.DylinkInfo.RebaseLen = uint32(len(rebaseDat))
	f.DylinkInfo.RebaseOffset = offset
	offset += uint64(len(rebaseDat))

	f.DylinkInfo.BindingInfoDat = bindDat
	f.DylinkInfo.BindingInfoLen = uint32(len(bindDat))
	f.DylinkInfo.BindingInfoOffset = offset
	offset += uint64(len(bindDat))

	f.DylinkInfo.WeakBindingDat = weakBindDat
	f.DylinkInfo.WeakBindingLen = uint32(len(weakBindDat))
	f.DylinkInfo.WeakBindingOffset = offset
	offset += uint64(len(weakBindDat))

	f.DylinkInfo.LazyBindingDat = lazyBindDat
	f.DylinkInfo.LazyBindingLen = uint32(len(lazyBindDat))
	f.DylinkInfo.LazyBindingOffset = offset

	return f.refreshDylinkInfoLoadBytes()
}

func (f *File) endOfSections() uint64 {
	var maxEnd uint64
	for _, s := range f.Sections {
		end := uint64(s.Offset) + s.Size
		if end > maxEnd {
			maxEnd = end
		}
	}
	return maxEnd
}

func (f *File) dyldInfoEndLimit() uint64 {
	var limit uint64
	setLimit := func(v uint64) {
		if v == 0 {
			return
		}
		if limit == 0 || v < limit {
			limit = v
		}
	}
	if f.FuncStarts != nil {
		setLimit(f.FuncStarts.Offset)
	}
	if f.DataInCode != nil {
		setLimit(f.DataInCode.Offset)
	}
	if f.Symtab != nil {
		setLimit(uint64(f.Symtab.Symoff))
	}
	if f.Dysymtab != nil {
		setLimit(uint64(f.Dysymtab.Indirectsymoff))
	}
	if f.SigBlock != nil {
		setLimit(f.SigBlock.Offset)
	}
	if f.DylinkInfo != nil {
		setLimit(f.DylinkInfo.LazyBindingOffset)
		setLimit(f.DylinkInfo.WeakBindingOffset)
		setLimit(f.DylinkInfo.ExportInfoOffset)
	}
	return limit
}

func (f *File) encodeDyldInfoFromRelocs() ([]byte, []byte, []byte, []byte, error) {
	segments := f.segmentOrdinals()
	if len(segments) == 0 {
		return nil, nil, nil, nil, nil
	}

	var rebase bytes.Buffer
	var bind bytes.Buffer
	var weak bytes.Buffer
	var lazy bytes.Buffer

	rebase.WriteByte(rebaseOpcodeSetTypeImm | rebaseTypePointer)
	bind.WriteByte(bindOpcodeSetTypeImm | bindTypePointer)
	weak.WriteByte(bindOpcodeSetTypeImm | bindTypePointer)
	lazy.WriteByte(bindOpcodeSetTypeImm | bindTypePointer)

	currentOrdinal := uint8(0)
	weakOrdinal := uint8(0)
	lazyOrdinal := uint8(0)
	bind.WriteByte(bindOpcodeSetDylibOrdinalImm | currentOrdinal)
	weak.WriteByte(bindOpcodeSetDylibOrdinalImm | weakOrdinal)
	lazy.WriteByte(bindOpcodeSetDylibOrdinalImm | lazyOrdinal)

	for _, s := range f.Sections {
		if len(s.Relocs) == 0 {
			continue
		}
		ordinal, ok := segments[s.Seg]
		if !ok {
			return nil, nil, nil, nil, fmt.Errorf("unknown segment for section %q", s.Name)
		}
		seg := byte(ordinal & 0x0f)
		for _, rel := range s.Relocs {
			offset := uint64(s.Addr) + uint64(rel.Addr)
			segBase := f.segmentAddr(s.Seg)
			if offset < segBase {
				return nil, nil, nil, nil, fmt.Errorf("relocation offset underflows segment %q", s.Seg)
			}
			segOffset := offset - segBase
			if rel.Extern {
				ordinal, err := f.dylibOrdinalForSymbol(rel.Value)
				if err != nil {
					return nil, nil, nil, nil, err
				}
				stream := &bind
				streamOrdinal := &currentOrdinal
				switch f.bindKindForSymbol(rel.Value) {
				case BindWeak:
					stream = &weak
					streamOrdinal = &weakOrdinal
				case BindLazy:
					stream = &lazy
					streamOrdinal = &lazyOrdinal
				}
				if ordinal != *streamOrdinal {
					stream.WriteByte(bindOpcodeSetDylibOrdinalImm | ordinal)
					*streamOrdinal = ordinal
				}
				name, err := f.symbolName(rel.Value)
				if err != nil {
					return nil, nil, nil, nil, err
				}
				stream.WriteByte(bindOpcodeSetSegmentAndOffsetULEB | seg)
				stream.Write(encodeULEB128(segOffset))
				stream.WriteByte(bindOpcodeSetSymbolTrailingFlags | 0)
				stream.WriteString(name)
				stream.WriteByte(0)
				stream.WriteByte(bindOpcodeDoBind)
			} else {
				rebase.WriteByte(rebaseOpcodeSetSegmentAndOffsetULEB | seg)
				rebase.Write(encodeULEB128(segOffset))
				rebase.WriteByte(rebaseOpcodeDoRebaseImmTimes | 1)
			}
		}
	}

	rebase.WriteByte(rebaseOpcodeDone)
	if bind.Len() > 1 {
		bind.WriteByte(bindOpcodeDone)
	}
	if weak.Len() > 1 {
		weak.WriteByte(bindOpcodeDone)
	}
	if lazy.Len() > 1 {
		lazy.WriteByte(bindOpcodeDone)
	}

	return rebase.Bytes(), bind.Bytes(), weak.Bytes(), lazy.Bytes(), nil
}

func (f *File) segmentOrdinals() map[string]int {
	ordinals := map[string]int{}
	ordinal := 0
	for _, load := range f.Loads {
		if seg, ok := load.(*Segment); ok {
			ordinals[seg.Name] = ordinal
			ordinal++
		}
	}
	return ordinals
}

func (f *File) segmentAddr(name string) uint64 {
	for _, load := range f.Loads {
		if seg, ok := load.(*Segment); ok && seg.Name == name {
			return seg.Addr
		}
	}
	return 0
}

func (f *File) symbolName(index uint32) (string, error) {
	if f.Symtab == nil {
		return "", errors.New("symbol table not available")
	}
	if int(index) >= len(f.Symtab.Syms) {
		return "", fmt.Errorf("symbol index %d out of range", index)
	}
	return f.Symtab.Syms[index].Name, nil
}

func (f *File) dylibOrdinalForSymbol(index uint32) (uint8, error) {
	if f.dylibOrdinalBySymbol == nil {
		return 0, nil
	}
	ordinal := f.dylibOrdinalBySymbol[index]
	if ordinal > 15 {
		return 0, fmt.Errorf("dylib ordinal %d out of range", ordinal)
	}
	return ordinal, nil
}

func (f *File) bindKindForSymbol(index uint32) BindKind {
	if f.bindKindBySymbol == nil {
		return BindNormal
	}
	return f.bindKindBySymbol[index]
}

func encodeULEB128(value uint64) []byte {
	var out []byte
	for {
		b := byte(value & 0x7f)
		value >>= 7
		if value != 0 {
			b |= 0x80
		}
		out = append(out, b)
		if value == 0 {
			break
		}
	}
	return out
}

func (f *File) maxFileOffset() uint64 {
	var maxEnd uint64
	for _, s := range f.Sections {
		end := uint64(s.Offset) + s.Size
		if end > maxEnd {
			maxEnd = end
		}
	}
	if f.DylinkInfo != nil {
		maxEnd = maxUint64(maxEnd, uint64(f.DylinkInfo.RebaseOffset)+uint64(f.DylinkInfo.RebaseLen))
		maxEnd = maxUint64(maxEnd, uint64(f.DylinkInfo.BindingInfoOffset)+uint64(f.DylinkInfo.BindingInfoLen))
		maxEnd = maxUint64(maxEnd, uint64(f.DylinkInfo.LazyBindingOffset)+uint64(f.DylinkInfo.LazyBindingLen))
		maxEnd = maxUint64(maxEnd, uint64(f.DylinkInfo.ExportInfoOffset)+uint64(f.DylinkInfo.ExportInfoLen))
		maxEnd = maxUint64(maxEnd, uint64(f.DylinkInfo.WeakBindingOffset)+uint64(f.DylinkInfo.WeakBindingLen))
	}
	if f.FuncStarts != nil {
		maxEnd = maxUint64(maxEnd, f.FuncStarts.Offset+uint64(f.FuncStarts.Len))
	}
	if f.DataInCode != nil {
		maxEnd = maxUint64(maxEnd, f.DataInCode.Offset+uint64(f.DataInCode.Len))
	}
	if f.Symtab != nil {
		maxEnd = maxUint64(maxEnd, uint64(f.Symtab.Symoff)+uint64(len(f.Symtab.RawSymtab)))
		maxEnd = maxUint64(maxEnd, uint64(f.Symtab.Stroff)+uint64(len(f.Symtab.RawStringtab)))
	}
	if f.Dysymtab != nil {
		maxEnd = maxUint64(maxEnd, uint64(f.Dysymtab.Indirectsymoff)+uint64(len(f.Dysymtab.RawDysymtab)))
	}
	if f.SigBlock != nil {
		maxEnd = maxUint64(maxEnd, f.SigBlock.Offset+uint64(f.SigBlock.Len))
	}
	if FinalSegEnd > maxEnd {
		maxEnd = FinalSegEnd
	}
	return maxEnd
}

func encodeRelocations(order binary.ByteOrder, relocs []Reloc) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	for _, rel := range relocs {
		ri, err := encodeRelocInfo(rel, order)
		if err != nil {
			return nil, err
		}
		if err := binary.Write(buf, order, ri); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func encodeRelocInfo(rel Reloc, order binary.ByteOrder) (relocInfo, error) {
	var ri relocInfo
	if rel.Scattered {
		addr := rel.Addr & (1<<24 - 1)
		addr |= uint32(rel.Type&0xf) << 24
		addr |= uint32(rel.Len&0x3) << 28
		if rel.Pcrel {
			addr |= 1 << 30
		}
		addr |= 1 << 31
		ri.Addr = addr
		ri.Symnum = rel.Value
		return ri, nil
	}
	ri.Addr = rel.Addr
	switch order {
	case binary.LittleEndian:
		symnum := rel.Value & (1<<24 - 1)
		if rel.Pcrel {
			symnum |= 1 << 24
		}
		symnum |= uint32(rel.Len&0x3) << 25
		if rel.Extern {
			symnum |= 1 << 27
		}
		symnum |= uint32(rel.Type&0xf) << 28
		ri.Symnum = symnum
	case binary.BigEndian:
		symnum := (rel.Value << 8) | uint32(rel.Type&0xf)
		if rel.Extern {
			symnum |= 1 << 4
		}
		symnum |= uint32(rel.Len&0x3) << 5
		if rel.Pcrel {
			symnum |= 1 << 7
		}
		ri.Symnum = symnum
	default:
		return ri, fmt.Errorf("unsupported byte order")
	}
	return ri, nil
}

func (f *File) refreshSegmentLoadBytes() error {
	is64 := f.Magic == Magic64
	for _, load := range f.Loads {
		seg, ok := load.(*Segment)
		if !ok {
			continue
		}
		raw, err := rebuildSegmentLoadBytes(seg, f.Sections, f.ByteOrder, is64)
		if err != nil {
			return err
		}
		seg.LoadBytes = raw
	}
	return nil
}

func (f *File) refreshDylinkInfoLoadBytes() error {
	if f.DylinkInfo == nil {
		return nil
	}
	for i, load := range f.Loads {
		raw, ok := load.(LoadBytes)
		if !ok || len(raw) < 8 {
			continue
		}
		cmd := LoadCmd(f.ByteOrder.Uint32(raw[0:4]))
		if cmd != LoadCmdDylinkInfo {
			continue
		}
		var hdr DylinkInfoCmd
		if err := binary.Read(bytes.NewReader(raw), f.ByteOrder, &hdr); err != nil {
			return err
		}
		if f.DylinkInfo.RebaseLen > 0 {
			hdr.Rebaseoff = uint32(f.DylinkInfo.RebaseOffset)
			hdr.Rebasesize = f.DylinkInfo.RebaseLen
		}
		if f.DylinkInfo.BindingInfoLen > 0 {
			hdr.Bindinginfooff = uint32(f.DylinkInfo.BindingInfoOffset)
			hdr.Bindinginfosize = f.DylinkInfo.BindingInfoLen
		}
		if f.DylinkInfo.WeakBindingLen > 0 {
			hdr.Weakbindingoff = uint32(f.DylinkInfo.WeakBindingOffset)
			hdr.Weakbindingsize = f.DylinkInfo.WeakBindingLen
		}
		if f.DylinkInfo.LazyBindingLen > 0 {
			hdr.Lazybindingoff = uint32(f.DylinkInfo.LazyBindingOffset)
			hdr.Lazybindingsize = f.DylinkInfo.LazyBindingLen
		}
		if f.DylinkInfo.ExportInfoLen > 0 {
			hdr.Exportinfooff = uint32(f.DylinkInfo.ExportInfoOffset)
			hdr.Exportinfosize = f.DylinkInfo.ExportInfoLen
		}
		buf := &bytes.Buffer{}
		if err := binary.Write(buf, f.ByteOrder, &hdr); err != nil {
			return err
		}
		f.Loads[i] = LoadBytes(buf.Bytes())
		return nil
	}
	return nil
}

func rebuildSegmentLoadBytes(seg *Segment, sections []*Section, order binary.ByteOrder, is64 bool) ([]byte, error) {
	r := bytes.NewReader(seg.LoadBytes)
	w := bytes.NewBuffer(nil)
	if is64 {
		var hdr Segment64
		if err := binary.Read(r, order, &hdr); err != nil {
			return nil, err
		}
		if err := binary.Write(w, order, &hdr); err != nil {
			return nil, err
		}
		for i := 0; i < int(hdr.Nsect); i++ {
			var sh Section64
			if err := binary.Read(r, order, &sh); err != nil {
				return nil, err
			}
			if match := matchSection(sections, cstring(sh.Name[:]), cstring(sh.Seg[:]), sh.Offset, sh.Addr); match != nil {
				sh.Reloff = match.Reloff
				sh.Nreloc = match.Nreloc
				sh.Addr = match.Addr
				sh.Size = match.Size
				sh.Offset = match.Offset
				sh.Align = match.Align
				sh.Flags = match.Flags
			}
			if err := binary.Write(w, order, &sh); err != nil {
				return nil, err
			}
		}
		return w.Bytes(), nil
	}

	var hdr Segment32
	if err := binary.Read(r, order, &hdr); err != nil {
		return nil, err
	}
	if err := binary.Write(w, order, &hdr); err != nil {
		return nil, err
	}
	for i := 0; i < int(hdr.Nsect); i++ {
		var sh Section32
		if err := binary.Read(r, order, &sh); err != nil {
			return nil, err
		}
		if match := matchSection(sections, cstring(sh.Name[:]), cstring(sh.Seg[:]), sh.Offset, uint64(sh.Addr)); match != nil {
			sh.Reloff = match.Reloff
			sh.Nreloc = match.Nreloc
			sh.Addr = uint32(match.Addr)
			sh.Size = uint32(match.Size)
			sh.Offset = match.Offset
			sh.Align = match.Align
			sh.Flags = match.Flags
		}
		if err := binary.Write(w, order, &sh); err != nil {
			return nil, err
		}
	}
	return w.Bytes(), nil
}

func matchSection(sections []*Section, name, seg string, offset uint32, addr uint64) *Section {
	var fallback *Section
	for _, s := range sections {
		if s.Name != name || s.Seg != seg {
			continue
		}
		if s.Offset == offset || s.Addr == addr {
			return s
		}
		if fallback == nil {
			fallback = s
		}
	}
	return fallback
}

func alignUp64(value, align uint64) uint64 {
	if align == 0 {
		return value
	}
	rem := value % align
	if rem == 0 {
		return value
	}
	return value + (align - rem)
}

func maxUint64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
