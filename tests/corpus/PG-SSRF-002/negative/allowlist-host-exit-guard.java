// corpus: expect=low
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
  private static final Set<String> ALLOWED = Set.of("api.example.com");
  @GetMapping("/fetch")
  public void fetch(@RequestParam String url, @RequestParam String id) throws Exception {
    URI target = URI.create(url);
    if (!ALLOWED.contains(target.getHost())) {
      throw new IllegalArgumentException("host not allowed");
    }
    return rest.getForObject(target, String.class);
  }
}
