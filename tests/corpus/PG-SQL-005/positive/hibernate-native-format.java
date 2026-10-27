// corpus: expect=PG-SQL-005
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import org.hibernate.Session;

public class ReportDao {
  public List<Object[]> totals(Session session, HttpServletRequest req) {
    String region = req.getParameter("region");
    String sql = String.format("SELECT region, SUM(total) FROM sales WHERE region = '%s' GROUP BY region", region);
    return session.createNativeQuery(sql).list();
  }
}
