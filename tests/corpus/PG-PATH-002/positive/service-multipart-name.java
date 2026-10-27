// corpus: expect=PG-PATH-002
import java.io.File;
import java.io.IOException;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

@Service
class StorageService {
  private final File root = new File("/srv/uploads");

  void store(MultipartFile file) throws IOException {
    file.transferTo(new File(root, file.getOriginalFilename()));
  }
}
