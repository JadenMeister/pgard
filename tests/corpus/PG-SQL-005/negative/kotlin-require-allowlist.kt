// corpus: expect=low
package com.example.sort

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

private val ALLOWED = setOf("name", "created_at")

@RestController
class SortedController(private val jdbcTemplate: JdbcTemplate) {
    @GetMapping("/sorted")
    fun sorted(@RequestParam sort: String): List<Map<String, Any>> {
        require(sort in ALLOWED) { "unsupported sort column" }
        return jdbcTemplate.queryForList("SELECT * FROM rows ORDER BY $sort")
    }
}
