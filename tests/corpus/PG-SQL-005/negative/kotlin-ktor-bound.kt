// corpus: expect=none
package com.example.ktor

import io.ktor.server.application.Application
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import java.sql.Connection

fun Application.routes(connection: Connection) {
    routing {
        get("/users/{name}") {
            val name = call.parameters["name"]
            val ps = connection.prepareStatement("SELECT id FROM users WHERE name = ?")
            ps.setString(1, name)
            ps.executeQuery()
        }
    }
}
