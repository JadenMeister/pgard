// corpus: expect=none
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;

class AuthController {
  ResponseEntity<Void> logout() {
    ResponseCookie cookie = ResponseCookie.from("sessionId", "").maxAge(0).path("/").build();
    return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString()).build();
  }
}
