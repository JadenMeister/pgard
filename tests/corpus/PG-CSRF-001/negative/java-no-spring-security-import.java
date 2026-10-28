// corpus: expect=none
// A tiny home-made builder named like Spring's: nothing here is Spring Security.
class Builder {
  Builder csrf() { return this; }
  void disable() {}
  void run() { new Builder().csrf().disable(); }
}
