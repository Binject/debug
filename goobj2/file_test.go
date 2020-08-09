package goobj2

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Binject/debug/goobj2/internal/bio"
	"github.com/kr/pretty"
)

const objPath = "hello_world.o"

var (
	newObjPath     = filepath.Join(filepath.Dir(objPath), "new_"+filepath.Base(objPath))
	newPureObjPath = filepath.Join(filepath.Dir(newObjPath), "pure_"+filepath.Base(newObjPath))
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
	obj2, err := Parse(f2, "")
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(obj, obj2) {
		t.Fatalf("not equal:\n%v", strings.Join(pretty.Diff(obj, obj2), "\n"))
	}
}
