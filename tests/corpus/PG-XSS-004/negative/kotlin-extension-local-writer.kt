// corpus: expect=none
import java.io.StringWriter

fun List<String>.csv(): String {
    val writer = StringWriter()
    forEach { writer.write(it + ",") }
    return writer.toString()
}
