// corpus: expect=PG-PATH-002
import java.io.File
import java.util.zip.ZipFile

fun unzipAll(zip: ZipFile, dest: File) {
    for (e in zip.entries()) {
        File(dest, e.name).mkdirs()
    }
}
