// corpus: expect=none
class Cleaner {
    private val base = "/var/cache/app"

    fun clean() {
        ProcessBuilder("find", "/var/cache/app", "-type", "f", "-delete").start()
        Runtime.getRuntime().exec("sync")
    }
}
