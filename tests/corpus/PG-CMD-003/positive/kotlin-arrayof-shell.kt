// corpus: expect=PG-CMD-003
import javax.servlet.http.HttpServletRequest

class Runner {
    fun run(request: HttpServletRequest) {
        val script = request.getParameter("script")
        Runtime.getRuntime().exec(arrayOf("/bin/bash", "-c", script))
    }
}
