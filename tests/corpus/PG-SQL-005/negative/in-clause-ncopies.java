// corpus: expect=none
import java.util.Collections;
import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;

class BatchDao {
  private JdbcTemplate jdbc;

  List<String> byIds(List<Long> ids) {
    String marks = String.join(",", Collections.nCopies(ids.size(), "?"));
    return jdbc.queryForList("SELECT name FROM items WHERE id IN (" + marks + ")", String.class, ids.toArray());
  }
}
