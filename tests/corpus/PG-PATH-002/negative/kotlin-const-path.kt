// corpus: expect=none
import java.io.File

class Defaults {
    companion object {
        const val DIR = "/etc/app"
    }

    fun text(): String = File(DIR, "defaults.conf").readText()
}
