// corpus: expect=PG-COOKIE-001
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;

class AuthController {
  ResponseEntity<Void> login(String id) {
    return ResponseEntity.ok()
        .header(HttpHeaders.SET_COOKIE,
            ResponseCookie.from("access_token", id).httpOnly(false).secure(true).sameSite("Lax").build().toString())
        .build();
  }
}
