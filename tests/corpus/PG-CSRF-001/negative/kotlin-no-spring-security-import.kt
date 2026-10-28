// corpus: expect=none
// A property called csrf on a plain class.
class Settings {
  var csrf: Toggle = Toggle()
  fun relax() { csrf.disable() }
}
class Toggle { fun disable() {} }
