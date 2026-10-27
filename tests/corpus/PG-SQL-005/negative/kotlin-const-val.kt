// corpus: expect=none
package com.example.reports

import org.springframework.jdbc.core.JdbcTemplate

private const val TABLE = "yearly_report"
private const val COLUMNS = "id, year, total"

class ReportRepository(private val jdbcTemplate: JdbcTemplate) {
    companion object {
        const val ORDER = " ORDER BY year DESC"
    }

    fun latest(): List<Map<String, Any>> {
        return jdbcTemplate.queryForList("SELECT $COLUMNS FROM $TABLE$ORDER LIMIT 5")
    }
}
