// corpus: expect=PG-SSRF-002
import java.net.URI;
import java.net.URL;
import java.util.Map;
import java.util.Set;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
public class FetchController {
  private final RestTemplate rest = new RestTemplate();

  @GetMapping("/fetch")
  public void fetch(@RequestParam String url, @RequestParam String id) throws Exception {
    return rest.getForObject(URI.create("https://api.example.com/v1/").resolve(url), String.class);
  }
}
