// corpus: expect=none
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

class ReportDao {
  private static final String TABLE = "monthly_report";
  private static final String COLUMNS = "id, month, total";
  private static final String BASE = "SELECT " + COLUMNS + " FROM " + TABLE;
  static final String ORDER = " ORDER BY month DESC";

  ResultSet latest(Connection connection) throws SQLException {
    Statement st = connection.createStatement();
    return st.executeQuery(BASE + ORDER + " LIMIT 12");
  }
}
