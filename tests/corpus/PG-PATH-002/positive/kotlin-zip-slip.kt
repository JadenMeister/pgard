// corpus: expect=PG-PATH-002
import java.io.File
import java.io.InputStream
import java.util.zip.ZipInputStream

class KotlinUnzipper {
    fun unzip(input: InputStream, dest: File) {
        ZipInputStream(input).use { zip ->
            var entry = zip.nextEntry
            while (entry != null) {
                val out = File(dest, entry.name)
                out.outputStream().use { zip.copyTo(it) }
                entry = zip.nextEntry
            }
        }
    }
}
