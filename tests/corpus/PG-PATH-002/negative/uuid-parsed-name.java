// corpus: expect=low
import java.io.File;
import java.util.UUID;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
class AvatarController {
  @GetMapping("/avatar/{id}")
  File avatar(@PathVariable String id) {
    UUID parsed = UUID.fromString(id);
    return new File("/srv/avatars/" + parsed + ".png");
  }
}
