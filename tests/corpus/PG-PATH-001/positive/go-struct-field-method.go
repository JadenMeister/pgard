// corpus: expect=PG-PATH-001
package main

import (
	"net/http"
	"os"
)

type store struct {
	file string
}

func (s store) read() ([]byte, error) { return os.ReadFile(s.file) }

func download(w http.ResponseWriter, r *http.Request) {
	s := store{file: r.FormValue("file")}
	data, _ := s.read()
	w.Write(data)
}
