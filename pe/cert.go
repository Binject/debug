package pe

import (
	"errors"
	"fmt"
	"io"
)

// CERTIFICATE_TABLE is the index of the Certificate Table info in the Data Directory structure
// in the PE header
const CERTIFICATE_TABLE = 4

func readCertTable(f *File, r io.ReadSeeker) ([]byte, error) {
	_, certTableOffset, certTableSize, err := getCertTableInfo(f)
	if err != nil {
		return nil, err
	}
	// check if certificate table exists
	if certTableOffset == 0 || certTableSize == 0 {
		return nil, nil
	}

	_, err = r.Seek(certTableOffset, seekStart)
	if err != nil {
		return nil, fmt.Errorf("fail to seek to certificate table: %v", err)
	}

	// grab the cert
	cert := make([]byte, certTableSize)
	_, err = io.ReadFull(r, cert)
	if err != nil {
		return nil, fmt.Errorf("fail to read certificate table: %v", err)
	}

	return cert, nil
}

// getCertTableInfo takes a PE file and returns the Certificate Table location,
// offset, and length
func getCertTableInfo(f *File) (int64, int64, int64, error) {
	peHeaderLoc := f.DosHeader.AddressOfNewExeHeader
	peHeaderLoc += 4

	var certTableDataLoc uint32
	var certTableOffset uint32
	var certTableSize uint32

	switch f.FileHeader.Machine {
	case IMAGE_FILE_MACHINE_I386:
		optionalHeader := f.OptionalHeader.(*OptionalHeader32)
		certTableDataLoc = peHeaderLoc + 20 + 128
		certTableOffset = optionalHeader.DataDirectory[CERTIFICATE_TABLE].VirtualAddress
		certTableSize = optionalHeader.DataDirectory[CERTIFICATE_TABLE].Size
	case IMAGE_FILE_MACHINE_AMD64:
		optionalHeader := f.OptionalHeader.(*OptionalHeader64)
		certTableDataLoc = peHeaderLoc + 20 + 144
		certTableOffset = optionalHeader.DataDirectory[CERTIFICATE_TABLE].VirtualAddress
		certTableSize = optionalHeader.DataDirectory[CERTIFICATE_TABLE].Size
	default:
		return 0, 0, 0, errors.New("architecture not supported")
	}

	return int64(certTableDataLoc), int64(certTableOffset), int64(certTableSize), nil
}