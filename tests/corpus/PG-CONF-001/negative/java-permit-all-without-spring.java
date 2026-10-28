// corpus: expect=none
class Access {
  Access permitAll() { return this; }
  Access anyRequest() { return this; }
  void run() { new Access().anyRequest().permitAll(); }
}
