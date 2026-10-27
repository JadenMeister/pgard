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
  public void fetch(@RequestParam String url, @RequestParam String id) throws Exception {
    java.net.InetAddress addr = java.net.InetAddress.getByName(new URL(url).getHost());
    if (addr.isLoopbackAddress() || addr.isSiteLocalAddress() || addr.isLinkLocalAddress()) {
      throw new IllegalArgumentException("private address");
    }
    return rest.getForObject(url, String.class);
  }
}
