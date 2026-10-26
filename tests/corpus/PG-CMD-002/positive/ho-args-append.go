// corpus: expect=PG-CMD-002
package ops

import (
	"net/http"
	"os/exec"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	args := []string{"-c"}
	args = append(args, r.FormValue("cmd"))
	out, _ := exec.Command("sh", args...).Output()
	w.Write(out)
}
