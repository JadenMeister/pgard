// corpus: expect=low
package com.example.ktor

import io.ktor.server.application.Application
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import java.sql.Connection

fun Application.pages(connection: Connection) {
    routing {
        get("/rows") {
            val limit = call.parameters["limit"]!!.toInt()
            connection.createStatement().executeQuery("SELECT * FROM rows LIMIT $limit")
        }
    }
}
