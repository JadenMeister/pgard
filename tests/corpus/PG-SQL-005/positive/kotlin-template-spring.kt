// corpus: expect=PG-SQL-005
package com.example.shop

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class ShopController(private val jdbcTemplate: JdbcTemplate) {
    @GetMapping("/items")
    fun items(@RequestParam category: String, @RequestParam maxPrice: String): List<Map<String, Any>> {
        val sql = "SELECT * FROM items WHERE category = '$category' AND price < ${maxPrice}"
        return jdbcTemplate.queryForList(sql)
    }
}
