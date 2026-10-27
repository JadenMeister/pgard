// corpus: expect=none
import io.ktor.client.HttpClient
import io.ktor.server.application.ApplicationCall

fun labels(call: ApplicationCall, client: HttpClient, names: Map<String, String>): String? {
    val key = call.parameters["key"]!!
    return names.get(key)
}
