// corpus: expect=PG-XSS-004
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

fun greet(req: HttpServletRequest, resp: HttpServletResponse) {
    resp.contentType = "text/html"
    resp.writer.write("<p>" + req.getParameter("name") + "</p>")
}
