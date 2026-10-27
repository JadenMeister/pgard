// corpus: expect=PG-CMD-003
import javax.servlet.http.HttpServletRequest

class PdfExporter {
    fun export(request: HttpServletRequest) {
        val page = request.getParameter("url")
        ProcessBuilder(*arrayOf("wkhtmltopdf", page, "out.pdf")).start()
    }
}
