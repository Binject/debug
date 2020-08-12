package goobj2

import (
	"bytes"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Binject/debug/goobj2/internal/bio"
	"github.com/kr/pretty"
)

func getNewObjPath(objPath string) string {
	return filepath.Join(filepath.Dir(objPath), "new_"+filepath.Base(objPath))
}

type test struct {
	name string
	path string
}

func TestWrite(t *testing.T) {
	var tests []test

	filepath.Walk("testdata", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			t.Fatalf("failed to walk testdata dir: %v", err)
		}

		if info.IsDir() {
			return nil
		}

		tests = append(tests, test{info.Name(), path})

		return nil
	})

	tempDir := t.TempDir()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			basename := strings.TrimSuffix(tt.name, filepath.Ext(tt.name))
			objPath := filepath.Join(tempDir, basename+".o")
			cmd := exec.Command("go", "tool", "compile", "-o", objPath, tt.path)
			if err := cmd.Run(); err != nil {
				t.Fatalf("failed to compile: %v", err)
			}

			// parse obj file
			f, err := os.Open(objPath)
			if err != nil {
				t.Fatalf("failed to open object file: %v", err)
			}
			defer f.Close()

			pkg, err := Parse(f, "")
			if err != nil {
				t.Fatalf("failed to parse object file: %v", err)
			}
			//ioutil.WriteFile(objPath+"_parsed", []byte(pretty.Sprint(pkg)), 0777)

			// write obj file
			newObjPath := getNewObjPath(objPath)
			b, err := bio.Create(newObjPath)
			if err != nil {
				t.Fatalf("failed to create new object file: %v", err)
			}
			WriteObjFile2(pkg, b, "")

			// compare bytes of the original and written object files
			objBytes, err := ioutil.ReadFile(objPath)
			if err != nil {
				t.Fatalf("failed to read object file: %v", err)
			}
			newObjBytes, err := ioutil.ReadFile(newObjPath)
			if err != nil {
				t.Fatalf("failed to read new object file: %v", err)
			}

			if !bytes.Equal(objBytes, newObjBytes) {
				t.Error("object files are not the same")
			}

			f2, err := os.Open(newObjPath)
			if err != nil {
				t.Fatal(err)
			}
			defer f2.Close()

			// compare parsed packages of the two object files
			pkg2, err := Parse(f2, "")
			if err != nil {
				t.Fatalf("failed to open new object file: %v", err)
			}

			if !reflect.DeepEqual(pkg, pkg2) {
				t.Errorf("Packages are not equal:\n%v", strings.Join(pretty.Diff(pkg, pkg2), "\n"))
			}
		})
	}
}