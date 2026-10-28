// corpus: expect=none
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;

class AuthController {
  ResponseEntity<Void> login(ResponseCookie built) {
    return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, built.toString()).build();
  }
}
