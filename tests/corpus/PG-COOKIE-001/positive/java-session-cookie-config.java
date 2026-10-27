// corpus: expect=PG-COOKIE-001
import javax.servlet.ServletContext;

class Init {
  void onStartup(ServletContext context) {
    context.getSessionCookieConfig().setHttpOnly(false);
  }
}
