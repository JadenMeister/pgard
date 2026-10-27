// corpus: expect=PG-CMD-003
import java.io.File;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;

class ReportRunner {
  void run(HttpServletRequest req) throws IOException {
    String report = req.getParameter("report");
    Runtime.getRuntime().exec("generate-report --name " + report, null, new File("/opt/reports"));
  }
}
