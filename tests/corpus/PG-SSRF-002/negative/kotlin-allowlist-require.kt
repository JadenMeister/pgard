// corpus: expect=low
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import java.net.URI

private val ALLOWED_HOSTS = setOf("api.example.com")

suspend fun fetch(client: HttpClient, url: String) {
    val host = URI(url).host
    require(host in ALLOWED_HOSTS) { "host not allowed" }
    client.get(url)
}
