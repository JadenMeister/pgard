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

  @GetMapping("/fetch")
  public String fetch(@RequestParam String url, @RequestParam String id) throws Exception {
    return rest.getForObject("https://api.example.com/users/" + id, String.class);
  }
}
