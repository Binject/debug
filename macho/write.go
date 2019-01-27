package macho

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io/ioutil"
	"log"
	"os"
	"sort"
)

// Write - Writes an *macho.File to disk
func (machoFile *File) Write(destFile string) error {

	bytesWritten := uint64(0)
	f, err := os.Create(destFile)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)

	// Write entire file header.
	buf := &bytes.Buffer{}
	err = binary.Write(buf, machoFile.ByteOrder, machoFile.FileHeader)
	if err != nil {
		panic(err)
	}
	headerLength := len(buf.Bytes())
	binary.Write(w, machoFile.ByteOrder, machoFile.FileHeader)
	bytesWritten += uint64(headerLength)
	log.Printf("%x: Wrote file header of size: %v", bytesWritten, bytesWritten)

	// todo: Add a buffer of 4 bytes ?
	w.Write([]byte{0, 0, 0, 0})
	bytesWritten += 4

	// Write Load Commands Loop
	for _, singleLoad := range machoFile.Loads {
		buf2 := &bytes.Buffer{}
		err = binary.Write(buf2, machoFile.ByteOrder, singleLoad.Raw())
		if err != nil {
			panic(err)
		}
		LoadCmdLen := len(buf2.Bytes())
		binary.Write(w, machoFile.ByteOrder, singleLoad.Raw())
		bytesWritten += uint64(LoadCmdLen)
		log.Printf("%x: Wrote Load Command, total size of: %v", bytesWritten, LoadCmdLen)
	}
	w.Flush()

	// Write Sections
	sortedSections := machoFile.Sections[:]
	sort.Slice(sortedSections, func(a, b int) bool { return machoFile.Sections[a].Offset < machoFile.Sections[b].Offset })
	for _, s := range sortedSections {

		log.Printf("%x: section/segment name: %s %s\n", bytesWritten, s.Name, s.Seg)

		if bytesWritten > uint64(s.Offset) {
			log.Printf("Overlapping Sections in Generated macho: %+v\n", s.Name)
			continue
		}
		if bytesWritten < uint64(s.Offset) {
			pad := make([]byte, uint64(s.Offset)-bytesWritten)
			w.Write(pad)
			bytesWritten += uint64(len(pad))
			log.Printf("%x: Padding: %+d bytes\n", bytesWritten, len(pad))
		}
		section, err := ioutil.ReadAll(s.Open())
		if err != nil {
			return err
		}
		binary.Write(w, machoFile.ByteOrder, section)
		bytesWritten += uint64(len(section))

		//if len(machoFile.Insertion) > 0 && s.Size-uint64(len(section)) == uint64(len(machoFile.Insertion)) {
		//	binary.Write(w, machoFile.ByteOrder, machoFile.Insertion)
		//	bytesWritten += uint64(len(machoFile.Insertion))
		//}
		w.Flush()
	}

	//Load command 3
	//cmd LC_SEGMENT_64
	//cmdsize 72
	//segname __LINKEDIT
	//fileoff 12288

	// Write Dynamic Loader Info if it exists
	if machoFile.DylinkInfo != nil {
		// Write Rebase if it exists
		if len(machoFile.DylinkInfo.RebaseDat) > 0 {
			log.Printf("Rebase Offset: %d", machoFile.DylinkInfo.RebaseOffset)
			if int64(machoFile.DylinkInfo.RebaseOffset)-int64(bytesWritten) > 0 {
				padA := make([]byte, machoFile.DylinkInfo.RebaseOffset-bytesWritten)
				w.Write(padA)
				log.Printf("wrote pad of: %d", len(padA))
				bytesWritten += uint64(len(padA))
				log.Printf("Bytes written: %d", bytesWritten)
			}
			log.Printf("Rebase: %+v \n", machoFile.DylinkInfo.RebaseDat)
			w.Write(machoFile.DylinkInfo.RebaseDat)
			log.Printf("Wrote raw Rebase, length of: %d", machoFile.DylinkInfo.RebaseLen)
			bytesWritten += uint64(machoFile.DylinkInfo.RebaseLen)
			log.Printf("Bytes written: %d", bytesWritten)
			w.Flush()
		}
		//Binding
		if len(machoFile.DylinkInfo.BindingInfoDat) > 0 {
			log.Printf("Binding Offset: %d", machoFile.DylinkInfo.BindingInfoOffset)
			if int64(machoFile.DylinkInfo.BindingInfoOffset)-int64(bytesWritten) > 0 {
				padB := make([]byte, machoFile.DylinkInfo.BindingInfoOffset-bytesWritten)
				w.Write(padB)
				log.Printf("wrote pad of: %d", len(padB))
				bytesWritten += uint64(len(padB))
				log.Printf("Bytes written: %d", bytesWritten)
			}
			log.Printf("Binding Info: %+v \n", machoFile.DylinkInfo.BindingInfoDat)
			w.Write(machoFile.DylinkInfo.BindingInfoDat)
			log.Printf("Wrote raw Binding Info, length of: %d", machoFile.DylinkInfo.BindingInfoLen)
			bytesWritten += uint64(machoFile.DylinkInfo.BindingInfoLen)
			log.Printf("Bytes written: %d", bytesWritten)
			w.Flush()
		}
		//Lazy
		if len(machoFile.DylinkInfo.LazyBindingDat) > 0 {
			log.Printf("Lazy Offset: %d", machoFile.DylinkInfo.LazyBindingOffset)
			if int64(machoFile.DylinkInfo.LazyBindingOffset)-int64(bytesWritten) > 0 {
				padD := make([]byte, machoFile.DylinkInfo.LazyBindingOffset-bytesWritten)
				w.Write(padD)
				log.Printf("wrote pad of: %d", len(padD))
				bytesWritten += uint64(len(padD))
				log.Printf("Bytes written: %d", bytesWritten)
			}
			log.Printf("Lazy Binding Data: %+v \n", machoFile.DylinkInfo.LazyBindingDat)
			w.Write(machoFile.DylinkInfo.LazyBindingDat)
			log.Printf("Wrote raw lazybinding, length of: %d", machoFile.DylinkInfo.LazyBindingLen)
			bytesWritten += uint64(machoFile.DylinkInfo.LazyBindingLen)
			log.Printf("Bytes written: %d", bytesWritten)
			w.Flush()
		}
		//Export
		if len(machoFile.DylinkInfo.ExportInfoDat) > 0 {
			log.Printf("Export Offset: %d", machoFile.DylinkInfo.ExportInfoOffset)
			if int64(machoFile.DylinkInfo.ExportInfoOffset)-int64(bytesWritten) > 0 {
				padE := make([]byte, machoFile.DylinkInfo.ExportInfoOffset-bytesWritten)
				w.Write(padE)
				log.Printf("wrote pad of: %d", len(padE))
				bytesWritten += uint64(len(padE))
				log.Printf("Bytes written: %d", bytesWritten)
			}
			log.Printf("Export Info: %+v \n", machoFile.DylinkInfo.ExportInfoDat)
			w.Write(machoFile.DylinkInfo.ExportInfoDat)
			log.Printf("Wrote raw Export Info, length of: %d", machoFile.DylinkInfo.ExportInfoLen)
			bytesWritten += uint64(machoFile.DylinkInfo.ExportInfoLen)
			log.Printf("Bytes written: %d", bytesWritten)
			w.Flush()
		}
		//Weak
		if len(machoFile.DylinkInfo.WeakBindingDat) > 0 {
			log.Printf("Weak Offset: %d", machoFile.DylinkInfo.WeakBindingOffset)
			if int64(machoFile.DylinkInfo.WeakBindingOffset)-int64(bytesWritten) > 0 {
				padC := make([]byte, machoFile.DylinkInfo.WeakBindingOffset-bytesWritten)
				w.Write(padC)
				log.Printf("wrote pad of: %d", len(padC))
				bytesWritten += uint64(len(padC))
				log.Printf("Bytes written: %d", bytesWritten)
			}
			log.Printf("Weak Binding: %+v \n", machoFile.DylinkInfo.WeakBindingDat)
			w.Write(machoFile.DylinkInfo.WeakBindingDat)
			log.Printf("Wrote raw Weak Binding, length of: %d", machoFile.DylinkInfo.WeakBindingLen)
			bytesWritten += uint64(machoFile.DylinkInfo.WeakBindingLen)
			log.Printf("Bytes written: %d", bytesWritten)
			w.Flush()
		}
	}

	// Write the Func Starts if they exist
	if machoFile.FuncStarts != nil {
		log.Printf("new pad: %d", machoFile.FuncStarts.Offset-bytesWritten)
		if int64(machoFile.FuncStarts.Offset)-int64(bytesWritten) > 0 {
			padY := make([]byte, machoFile.FuncStarts.Offset-bytesWritten)
			w.Write(padY)
			log.Printf("wrote pad of: %d", len(padY))
			bytesWritten += uint64(len(padY))
			log.Printf("Bytes written: %d", bytesWritten)
		}
		log.Printf("FuncStarts: %+v \n", machoFile.FuncStarts)
		w.Write(machoFile.FuncStarts.RawDat)
		log.Printf("Wrote raw funcstarts, length of: %d", machoFile.FuncStarts.Len)
		bytesWritten += uint64(machoFile.FuncStarts.Len)
		log.Printf("Bytes written: %d", bytesWritten)
		w.Flush()
	}

	// Write the Data in Code Entries if they exist
	if machoFile.DataInCode != nil {
		if int64(machoFile.DataInCode.Offset)-int64(bytesWritten) > 0 {
			padZ := make([]byte, machoFile.DataInCode.Offset-bytesWritten)
			w.Write(padZ)
			log.Printf("wrote pad of: %d", len(padZ))
			bytesWritten += uint64(len(padZ))
			log.Printf("Bytes written: %d", bytesWritten)
		}
		log.Printf("DataInCode: %+v \n", machoFile.DataInCode)
		w.Write(machoFile.DataInCode.RawDat)
		log.Printf("Wrote raw dataincode, length of: %d", machoFile.DataInCode.Len)
		bytesWritten += uint64(machoFile.DataInCode.Len)
		log.Printf("Bytes written: %d", bytesWritten)
		w.Flush()
	}

	// Write Symbols is next I think
	symtab := machoFile.Symtab
	log.Printf("Bytes written: %d", bytesWritten)
	log.Printf("Indirect symbol offset: %d", machoFile.Dysymtab.DysymtabCmd.Indirectsymoff)
	log.Printf("Locrel offset: %d", machoFile.Dysymtab.Locreloff)
	log.Printf("Symtab offset: %d", symtab.Symoff)
	log.Printf("String table offset: %d", symtab.Stroff)
	if int64(symtab.Symoff)-int64(bytesWritten) > 0 {
		pad := make([]byte, uint64(symtab.Symoff)-bytesWritten)
		w.Write(pad)
		log.Printf("wrote pad of: %d", uint64(symtab.Symoff)-bytesWritten)
		bytesWritten += (uint64(symtab.Symoff) - bytesWritten)
	}
	w.Write(symtab.RawSymtab)
	log.Printf("Wrote raw symtab, length of: %d", len(symtab.RawSymtab))
	bytesWritten += uint64(len(symtab.RawSymtab))
	log.Printf("Bytes written: %d", bytesWritten)

	// Write DySymTab next!
	dysymtab := machoFile.Dysymtab
	if int64(dysymtab.Indirectsymoff)-int64(bytesWritten) > 0 {
		pad2 := make([]byte, uint64(dysymtab.Indirectsymoff)-bytesWritten)
		w.Write(pad2)
		log.Printf("wrote pad of: %d", len(pad2))
		bytesWritten += uint64(len(pad2))
		log.Printf("Bytes written: %d", bytesWritten)
	}
	w.Write(dysymtab.RawDysymtab)
	log.Printf("Wrote raw indirect symbols, length of: %d", len(dysymtab.RawDysymtab))
	bytesWritten += uint64(len(dysymtab.RawDysymtab))
	log.Printf("Bytes written: %d", bytesWritten)

	// Write StringTab!
	if int64(symtab.Stroff)-int64(bytesWritten) > 0 {
		pad3 := make([]byte, uint64(symtab.Stroff)-bytesWritten)
		w.Write(pad3)
		log.Printf("wrote pad of: %d", len(pad3))
		bytesWritten += uint64(len(pad3))
		log.Printf("Bytes written: %d", bytesWritten)
	}
	w.Write(symtab.RawStringtab)
	log.Printf("Wrote raw stringtab, length of: %d", len(symtab.RawStringtab))
	bytesWritten += uint64(len(symtab.RawStringtab))
	log.Printf("Bytes written: %d", bytesWritten)
	w.Flush()

	// Write The Signature Block, if it exists
	//log.Printf("SigBlock Dat: %v", machoFile.SigBlock)
	if machoFile.SigBlock != nil {
		if int64(machoFile.SigBlock.Offset)-int64(bytesWritten) > 0 {
			padX := make([]byte, int64(machoFile.SigBlock.Offset)-int64(bytesWritten))
			w.Write(padX)
			log.Printf("wrote pad of: %d", len(padX))
			bytesWritten += uint64(len(padX))
			log.Printf("Bytes written: %d", bytesWritten)
		}
		w.Write(machoFile.SigBlock.RawDat)
		log.Printf("Wrote raw sigblock, length of: %d", machoFile.SigBlock.Len)
		bytesWritten += uint64(machoFile.SigBlock.Len)
		log.Printf("Bytes written: %d", bytesWritten)
		w.Flush()
	}

	// Write 0s to the end of the final segment
	if int64(FinalSegEnd)-int64(bytesWritten) > 0 {
		pad4 := make([]byte, uint64(FinalSegEnd)-bytesWritten)
		w.Write(pad4)
		log.Printf("wrote pad of: %d", len(pad4))
		bytesWritten += uint64(len(pad4))
		log.Printf("Bytes written: %d", bytesWritten)
		w.Flush()
	}

	w.Flush()
	log.Println("All done!")
	return nil
}
