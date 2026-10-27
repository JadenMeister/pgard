// corpus: expect=low
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class DotDotController {
  @GetMapping("/f")
  FileInputStream f(@RequestParam String name) throws IOException {
    if (name.contains("..") || name.contains("/")) {
      throw new IllegalArgumentException("bad name");
    }
    return new FileInputStream(new File("/srv/dd", name));
  }
}
