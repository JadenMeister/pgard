// corpus: expect=PG-SSRF-002
import java.net.URI;
import java.net.URL;
import java.util.Map;
import java.util.Set;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import okhttp3.OkHttpClient;

@RestController
public class FetchController {
  private final RestTemplate rest = new RestTemplate();

  @GetMapping("/fetch")
  public String fetch(@RequestParam String url, @RequestParam String id) throws Exception {
    okhttp3.Request request = new okhttp3.Request.Builder().url(url).build();
    return new okhttp3.OkHttpClient().newCall(request).execute().body().string();
  }
}
