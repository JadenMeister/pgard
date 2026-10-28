// corpus: expect=none
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;

class AuthController {
  ResponseEntity<Void> login(String id) {
    ResponseCookie cookie = ResponseCookie.from("sessionId", id)
        .httpOnly(true).secure(true).sameSite("Lax").path("/").build();
    return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString()).build();
  }
}
