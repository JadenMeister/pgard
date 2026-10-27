// corpus: expect=low
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.springframework.web.util.HtmlUtils

fun greet(req: HttpServletRequest, resp: HttpServletResponse) {
    resp.contentType = "text/html"
    resp.writer.write("<p>" + HtmlUtils.htmlEscape(req.getParameter("name")) + "</p>")
}
