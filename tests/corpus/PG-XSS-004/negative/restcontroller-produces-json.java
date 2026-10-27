// corpus: expect=none
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PageController {
  @GetMapping(value = "/greet", produces = MediaType.APPLICATION_JSON_VALUE)
  public String page(@RequestParam String name) {
    return "{\"name\":\"" + name + "\"}";
  }
}
