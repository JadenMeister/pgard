// corpus: expect=PG-CMD-002
package main

import (
	"net/http"
	"os/exec"
)

func run(w http.ResponseWriter, r *http.Request) {
	program := r.FormValue("tool")
	out, _ := exec.Command(program, "--version").Output()
	w.Write(out)
}
