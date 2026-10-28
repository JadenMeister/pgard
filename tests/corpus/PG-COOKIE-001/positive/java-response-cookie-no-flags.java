// corpus: expect=PG-COOKIE-001
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;

class AuthController {
  ResponseEntity<Void> login(String id) {
    ResponseCookie cookie = ResponseCookie.from("sessionId", id).path("/").build();
    return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString()).build();
  }
}
