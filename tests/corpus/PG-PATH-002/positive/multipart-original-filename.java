// corpus: expect=PG-PATH-002
import java.io.File;
import java.io.IOException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
class UploadController {
  @PostMapping("/upload")
  void upload(@RequestParam("file") MultipartFile file) throws IOException {
    File target = new File("/var/uploads/" + file.getOriginalFilename());
    file.transferTo(target);
  }
}
