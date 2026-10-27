// corpus: expect=none
import io.ktor.client.HttpClient
import io.ktor.client.request.get

suspend fun health(client: HttpClient) {
    client.get("https://api.example.com/health")
}
