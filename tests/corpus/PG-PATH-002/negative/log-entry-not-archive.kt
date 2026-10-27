// corpus: expect=low
import java.io.File
import java.util.zip.ZipFile

class LogEntry(val name: String)

fun saveLogs(entries: List<LogEntry>, dest: File) {
    for (logEntry: LogEntry in entries) {
        File(dest, logEntry.name).mkdirs()
    }
}
