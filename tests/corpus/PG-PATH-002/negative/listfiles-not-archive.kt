// corpus: expect=low
import java.io.File
import java.util.zip.ZipOutputStream

fun copyAll(dir: File, dest: File) {
    dir.listFiles()!!.forEach { File(dest, it.name).mkdirs() }
}
