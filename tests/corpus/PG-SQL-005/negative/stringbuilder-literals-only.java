// corpus: expect=none
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

class SearchDao {
  PreparedStatement build(Connection connection, String name, Integer minAge) throws SQLException {
    StringBuilder sql = new StringBuilder("SELECT * FROM people WHERE 1 = 1");
    if (name != null) {
      sql.append(" AND name = ?");
    }
    if (minAge != null) {
      sql.append(" AND age >= ?");
    }
    sql.append(" ORDER BY name");
    PreparedStatement ps = connection.prepareStatement(sql.toString());
    int i = 1;
    if (name != null) ps.setString(i++, name);
    if (minAge != null) ps.setInt(i, minAge);
    return ps;
  }
}
