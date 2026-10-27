// corpus: expect=PG-SSRF-002
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.server.application.ApplicationCall

suspend fun proxy(call: ApplicationCall, client: HttpClient) {
    val target = call.parameters["url"]!!
    client.get(target)
}
