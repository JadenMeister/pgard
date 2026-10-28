// corpus: expect=none
import javax.servlet.ServletContext;

class Init {
  void onStartup(ServletContext context) {
    context.getSessionCookieConfig().setHttpOnly(true);
    context.getSessionCookieConfig().setSecure(true);
  }
}
