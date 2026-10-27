// corpus: expect=PG-XSS-004
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@Controller
public class PageController {
  @GetMapping(value = "/greet", produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String page(@RequestParam String name) {
    return "<h1>Hello " + name + "</h1>";
  }
}
