package goobj2

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/Binject/debug/goobj2/internal/bio"
)

const (
	objPath        = "hello_world.o"
	newObjPath     = "new_" + objPath
	newPureObjPath = "new_" + objPath + "_pure"
)

func TestParse(t *testing.T) {
	f, err := os.Open(objPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// parse obj file
	obj, err := Parse(f, "")
	if err != nil {
		t.Fatal(err)
	}
	//pretty.Println(obj)

	// write obj file
	b, err := bio.Create(newObjPath)
	if err != nil {
		t.Fatal(err)
	}
	WriteObjFile2(obj, b, "")

	// create "pure" obj file
	objBytes, err := ioutil.ReadFile(newObjPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = ioutil.WriteFile(newPureObjPath, objBytes[405:], 0777); err != nil {
		t.Fatal(err)
	}

	f2, err := os.Open(newObjPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f2.Close()

	// test parsing written file
	_, err = Parse(f2, "")
	if err != nil {
		t.Fatal(err)
	}
}
