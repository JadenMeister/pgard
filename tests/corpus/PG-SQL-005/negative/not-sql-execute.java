// corpus: expect=none
import java.util.concurrent.ExecutorService;
import javax.servlet.http.HttpServletRequest;

class Jobs {
  private ExecutorService executor;

  void run(HttpServletRequest request) {
    String name = request.getParameter("job");
    executor.execute(new NamedTask("job-" + name));
  }
}
