// corpus: expect=PG-PATH-002
import java.io.File;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class ListingController {
  @GetMapping("/ls")
  String[] list(@RequestParam String dir) {
    File folder = new File("/srv/public/" + dir);
    return folder.list();
  }
}
