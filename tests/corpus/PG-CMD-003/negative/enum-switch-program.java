// corpus: expect=none
import java.io.IOException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class CompressController {
  @GetMapping("/compress")
  void compress(@RequestParam String kind) throws IOException {
    String tool;
    switch (kind) {
      case "gz": tool = "gzip"; break;
      case "bz": tool = "bzip2"; break;
      default: tool = "xz";
    }
    new ProcessBuilder(tool, "-k", "/data/archive.tar").start();
  }
}
