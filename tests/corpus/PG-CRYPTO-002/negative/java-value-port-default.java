// corpus: expect=none
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.nio.charset.StandardCharsets;
import org.springframework.beans.factory.annotation.Value;

public class Sample {
  @Value("${server.port:8080}") int port;
  @Value("${app.name:demo}") String name;
}
