package macho

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io/ioutil"
	"log"
	"os"
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

	// Write Macho Magic
	//err = binary.Write(w, machoFile.ByteOrder, machoFile.Magic)
	//if err != nil {
	//	panic(err)
	//}
	//bytesWritten += 4
	//log.Printf("Wrote magic header: %+v", machoFile.Magic)
	//w.Flush()

	// Write entire file header.
	buf := &bytes.Buffer{}
	err = binary.Write(buf, machoFile.ByteOrder, machoFile.FileHeader)
	if err != nil {
		panic(err)
	}
	headerLength := len(buf.Bytes())
	binary.Write(w, machoFile.ByteOrder, machoFile.FileHeader)
	bytesWritten += uint64(headerLength)
	log.Printf("Wrote file header of size: %v", bytesWritten)

	// Add a buffer of 4 bytes ?
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
		log.Printf("Wrote Load Command, total size of: %v", LoadCmdLen)
	}
	w.Flush()

	// Write Sections
	sortedSections := machoFile.Sections[:]
	//sort.Slice(sortedSections, func(a, b int) bool { return machoFile.Sections[a].Offset < machoFile.Sections[b].Offset })
	for _, s := range sortedSections {
		if bytesWritten > uint64(s.Offset) {
			log.Printf("Overlapping Sections in Generated macho: %+v\n", s.Name)
			continue
		}
		if bytesWritten < uint64(s.Offset) {
			align := uint64(s.Align)
			alignedOffset := uint64(0)
			if align != 0 {
				alignedOffset = ((uint64(s.Offset) / align) * align)
				pad := make([]byte, alignedOffset-bytesWritten)
				w.Write(pad)
				bytesWritten += uint64(len(pad))
			}
			log.Printf("Alignment Thing: %+v %d %x %d\n", s, align, s.Offset, alignedOffset-bytesWritten)
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

	// Write the rest

	w.Flush()
	log.Println("All done!")
	return nil
}