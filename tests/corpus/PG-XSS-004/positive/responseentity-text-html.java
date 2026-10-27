// corpus: expect=PG-XSS-004
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PageController {
  @GetMapping("/greet")
  public ResponseEntity<String> page(@RequestParam String name) {
    return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body("<p>" + name + "</p>");
  }
}
