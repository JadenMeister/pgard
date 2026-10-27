// corpus: expect=low
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.server.application.ApplicationCall

suspend fun user(call: ApplicationCall, client: HttpClient) {
    val id = call.parameters["id"]!!
    client.get("https://api.example.com/users/$id")
}
