// corpus: expect=none
import javax.servlet.http.HttpServletRequest;

class Dns {
  private final Resolver resolver;

  Dns(Resolver resolver) { this.resolver = resolver; }

  String lookup(HttpServletRequest request) {
    String host = request.getParameter("host");
    return resolver.resolve(host);
  }

  interface Resolver {
    String resolve(String host);
  }
}
