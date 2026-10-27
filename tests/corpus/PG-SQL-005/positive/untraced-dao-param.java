// corpus: expect=PG-SQL-005
import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;

class ColumnDao {
  private final JdbcTemplate jdbcTemplate;

  ColumnDao(JdbcTemplate jdbcTemplate) {
    this.jdbcTemplate = jdbcTemplate;
  }

  // No request input is visible here: the caller decides what `column` holds.
  List<String> distinct(String column) {
    return jdbcTemplate.queryForList("SELECT DISTINCT " + column + " FROM events", String.class);
  }
}
