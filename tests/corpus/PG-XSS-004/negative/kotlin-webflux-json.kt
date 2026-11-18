// corpus: expect=none
import org.springframework.http.MediaType
import org.springframework.web.reactive.function.server.ServerRequest
import org.springframework.web.reactive.function.server.ServerResponse
import org.springframework.web.reactive.function.server.bodyValueAndAwait

suspend fun ServerRequest.greet(): ServerResponse {
    val name = queryParam("name").orElse("world")
    return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON).bodyValueAndAwait("{\"hello\":\"$name\"}")
}
