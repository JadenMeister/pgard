// corpus: expect=none
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

  enum Feed { NEWS, SPORT }

  @GetMapping("/feed")
  public String feed() {
    String url = "https://feeds.example.com/news";
    return rest.getForObject(url, String.class);
  }
}
