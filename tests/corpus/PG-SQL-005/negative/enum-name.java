// corpus: expect=none
import org.springframework.jdbc.core.JdbcTemplate;

class SortedDao {
  enum Direction { ASC, DESC }

  private JdbcTemplate jdbc;

  Object page(Direction direction) {
    return jdbc.queryForList("SELECT * FROM events ORDER BY created_at " + direction.name());
  }

  Object newest() {
    return jdbc.queryForList("SELECT * FROM events ORDER BY created_at " + Direction.DESC.name());
  }
}
