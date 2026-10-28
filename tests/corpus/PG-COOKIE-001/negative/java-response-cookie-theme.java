// corpus: expect=none
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;

class PrefController {
  ResponseEntity<Void> theme() {
    ResponseCookie cookie = ResponseCookie.from("theme", "dark").path("/").build();
    return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString()).build();
  }
}
