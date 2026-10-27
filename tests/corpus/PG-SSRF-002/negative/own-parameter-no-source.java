// corpus: expect=low
import java.net.URI;
import java.net.URL;
import java.util.Map;
import java.util.Set;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

public class Client {
  private final RestTemplate rest = new RestTemplate();

  public String get(String endpoint) {
    return rest.getForObject(endpoint, String.class);
  }
}
