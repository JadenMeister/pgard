// corpus: expect=PG-XSS-004
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

fun HttpServletResponse.page(request: HttpServletRequest) {
    contentType = "text/html"
    writer.write("<p>" + request.getParameter("name") + "</p>")
}
