// corpus: expect=none
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

class Config {
  private static final String DIR = "/etc/app";

  byte[] load() throws IOException {
    File f = new File(DIR, "app.properties");
    try (FileInputStream in = new FileInputStream(f)) {
      in.read();
    }
    return Files.readAllBytes(Paths.get(DIR + "/defaults.properties"));
  }
}
