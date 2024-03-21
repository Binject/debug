package elf

import "os"

// Write creates or truncates the named file. If the file already exists,
// it is truncated. If the file does not exist, it is created with mode 0666
// (before umask). If there is an error, it will be of type *PathError.
func (f *File) Write(name string) error {
	fd, err1 := os.Create(name)
	if err1 != nil {
		return err1
	}
	data, err2 := f.Bytes()
	if err2 != nil {
		return err2
	}
	_, err3 := fd.Write(data)
	if err3 != nil {
		return err3
	}
	err4 := fd.Close()
	if err4 != nil {
		return err4
	}

	return nil
}
