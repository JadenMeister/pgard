// corpus: expect=none
class Cookie {
  Cookie(String name, String value) {}
}

class Holder {
  Cookie make(String id) {
    return new Cookie("sessionId", id);
  }
}
