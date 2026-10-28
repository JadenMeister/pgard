// corpus: expect=PG-COOKIE-001
import org.springframework.http.HttpHeaders
import org.springframework.http.ResponseCookie
import org.springframework.http.ResponseEntity

class AuthController {
  fun login(id: String): ResponseEntity<Void> {
    val cookie = ResponseCookie.from("session", id).path("/").build()
    return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString()).build()
  }
}
