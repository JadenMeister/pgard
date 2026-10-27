// corpus: expect=PG-SQL-005
package com.example.ktor

import io.ktor.server.application.Application
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import java.sql.Connection

fun Application.configureRouting(connection: Connection) {
    routing {
        get("/accounts/{id}") {
            val id = call.parameters["id"]
            val statement = connection.createStatement()
            val rs = statement.executeQuery("SELECT balance FROM accounts WHERE id = " + id)
            call.respondText(if (rs.next()) rs.getString(1) else "none")
        }
    }
}
