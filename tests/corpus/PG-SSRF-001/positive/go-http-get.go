// corpus: expect=PG-SSRF-001
package main

import (
	"io"
	"net/http"
)

func proxy(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get(r.URL.Query().Get("url"))
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}
