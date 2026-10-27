// corpus: expect=PG-SSRF-002
import okhttp3.OkHttpClient
import okhttp3.Request
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class FetchController(private val http: OkHttpClient) {
    @GetMapping("/fetch")
    fun fetch(@RequestParam url: String): String {
        val request = Request.Builder().url(url).build()
        return http.newCall(request).execute().body!!.string()
    }
}
