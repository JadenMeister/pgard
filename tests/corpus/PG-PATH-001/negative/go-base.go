// corpus: expect=none
package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func download(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.URL.Query().Get("name"))
	data, err := os.ReadFile(filepath.Join("/srv/files", name))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Write(data)
}
