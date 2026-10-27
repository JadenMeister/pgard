/**
 * Names the Java/Kotlin command execution (PG-CMD-003) and path traversal (PG-PATH-002) rules
 * recognize: process APIs, file APIs, archive entries and path conversions.
 */

// ------------------------------------------------------------------ command execution

/** Programs that read a script from their arguments (`sh -c`, `cmd /c`, `powershell -Command`). */
export const SHELL_PROGRAMS = new Set([
  "sh",
  "bash",
  "zsh",
  "dash",
  "ksh",
  "csh",
  "tcsh",
  "fish",
  "ash",
  "cmd",
  "powershell",
  "pwsh",
]);
/** The flag that makes each shell family run the next argument as a script. */
export const SHELL_FLAG_POSIX = /^-[a-zA-Z]*c[a-zA-Z]*$/;
export const SHELL_FLAG_CMD = /^\/[ckCK]$/;
export const SHELL_FLAG_PD = /^-(?:c|command|ec|encodedcommand)$/i;

/** A receiver of `exec(...)` that is a `Runtime` by its usual name. */
export const RUNTIME_NAME = /^(?:runtime|rt|jvmRuntime)$/i;

/** Types that hold several values (a command as an argument list), not one string. */
export const COLLECTION_TYPE =
  /\[\]|^(?:Array|List|MutableList|Collection|MutableCollection|Iterable|ArrayList|LinkedList|Set|Deque|Vector|Sequence)\b/;
/** Calls whose result is an array or a list. */
export const COLLECTION_RESULTS = new Set([
  "split",
  "toTypedArray",
  "toArray",
  "toList",
  "toMutableList",
  "asList",
  "lines",
  "stream",
]);
export const COLLECTION_CLASSES = new Set([
  "ArrayList",
  "LinkedList",
  "Vector",
  "ArrayDeque",
  "HashSet",
  "LinkedHashSet",
  "TreeSet",
]);
/** Calls on a list or array that put values into it. */
export const ELEMENT_WRITERS = new Set([
  "add",
  "addAll",
  "addFirst",
  "addLast",
  "set",
  "push",
  "offer",
  "offerFirst",
  "offerLast",
  "setAll",
]);

/** Calls that append to a list. */
export const ELEMENT_ADD = new Set(["add", "addAll", "addFirst", "addLast", "offer", "push"]);

export const IMPORTS_COMMONS_EXEC = "org.apache.commons.exec";

/** Libraries that run processes or touch files with their own API; the rules do not follow them. */
export const PROCESS_AND_FILE_LIBRARIES: ReadonlyArray<{
  prefix: string;
  label: string;
  kind: "process" | "file";
}> = [
  { prefix: "org.zeroturnaround.exec", label: "zt-exec", kind: "process" },
  { prefix: "com.zaxxer.nuprocess", label: "NuProcess", kind: "process" },
  { prefix: "okio", label: "Okio", kind: "file" },
  { prefix: "io.vertx.core.file", label: "Vert.x file system", kind: "file" },
  { prefix: "org.apache.commons.vfs2", label: "Commons VFS", kind: "file" },
];

// ------------------------------------------------------------------ archives (zip slip)

export const ARCHIVE_IMPORT_PREFIXES = [
  "java.util.zip",
  "java.util.jar",
  "org.apache.commons.compress",
  "net.lingala.zip4j",
  "org.rauschig.jarchivelib",
];
/** The type of a variable that holds an archive entry (the name inside it is chosen by the archive's author). */
export const ARCHIVE_ENTRY_TYPE = /(?:Zip|Jar|Tar|Cpio|Ar|SevenZ|Archive)\w*Entry$|^FileHeader$/;
/** A variable named like an archive entry (used only in a file that imports an archive library). */
export const ARCHIVE_ENTRY_NAME = /(?:^|[a-z])[Ee]ntry$|^ze$|^fileHeader$/;
/** Calls that return the next entry of an archive stream. */
export const ARCHIVE_NEXT = new Set([
  "getNextEntry",
  "getNextZipEntry",
  "getNextTarEntry",
  "getNextJarEntry",
  "getNextCpioEntry",
  "getNextArEntry",
  "nextEntry",
  "nextZipEntry",
  "nextTarEntry",
  "nextJarEntry",
  "nextCpioEntry",
  "nextArEntry",
  "getNextFileHeader",
]);

// ------------------------------------------------------------------ file paths

/** `Files.x(path, ...)`: the first argument is the path that is read or changed. */
export const FILES_SINKS = new Set([
  "readAllBytes",
  "readString",
  "readAllLines",
  "lines",
  "newInputStream",
  "newOutputStream",
  "newBufferedReader",
  "newBufferedWriter",
  "newByteChannel",
  "write",
  "writeString",
  "delete",
  "deleteIfExists",
  "createFile",
  "createDirectory",
  "createDirectories",
  "list",
  "walk",
  "newDirectoryStream",
]);
/** `Files.copy(from, to)` and `Files.move(from, to)`: either argument can be a path. */
export const FILES_TWO_PATH = new Set(["copy", "move"]);
/** Commons IO `FileUtils` calls that take the path (a `File`) as the first argument. */
export const FILEUTILS_SINKS = new Set([
  "readFileToString",
  "readFileToByteArray",
  "readLines",
  "lineIterator",
  "writeStringToFile",
  "writeByteArrayToFile",
  "writeLines",
  "write",
  "copyFile",
  "copyFileToDirectory",
  "copyDirectory",
  "copyToFile",
  "moveFile",
  "moveDirectory",
  "moveFileToDirectory",
  "openInputStream",
  "openOutputStream",
  "forceDelete",
  "deleteDirectory",
  "deleteQuietly",
  "cleanDirectory",
  "touch",
  "listFiles",
  "iterateFiles",
]);
/** Classes whose constructor opens the file it is given. */
export const FILE_OPENERS = new Set([
  "FileInputStream",
  "FileOutputStream",
  "FileReader",
  "FileWriter",
  "RandomAccessFile",
  "FileSystemResource",
  "PathResource",
  "PrintWriter",
  "PrintStream",
  "Formatter",
  "ZipFile",
  "JarFile",
  "FileHandler",
  "UrlResource",
]);
/** Openers that also take a stream or a writer: only a value that looks like a file name counts. */
export const POLY_OPENERS = new Set(["PrintWriter", "PrintStream", "Formatter"]);
/** Openers of a URL: only a `file:` URL is a file. */
export const URL_OPENERS = new Set(["UrlResource"]);
/** Calls on a path that read its metadata only (existence, size). */
export const FILES_PROBES = new Set([
  "exists",
  "notExists",
  "isDirectory",
  "isRegularFile",
  "isReadable",
  "isWritable",
  "isExecutable",
  "isHidden",
  "isSymbolicLink",
  "size",
  "getLastModifiedTime",
]);
export const FILE_PROBES = new Set([
  "exists",
  "isFile",
  "isDirectory",
  "isHidden",
  "length",
  "canRead",
  "canWrite",
  "canExecute",
  "lastModified",
]);
/** Types that hold an uploaded file (and the file name the client chose). */
export const UPLOAD_TYPES = new Set([
  "MultipartFile",
  "Part",
  "FilePart",
  "FileItem",
  "FileUpload",
  "UploadedFile",
]);
/** Programs that run the command that follows them. */
export const LAUNCHERS = new Set([
  "env",
  "sudo",
  "nohup",
  "timeout",
  "nice",
  "xargs",
  "doas",
  "stdbuf",
  "time",
]);
/** Receivers whose `entries()`, `stream()` and `getNextEntry()` give archive entries. */
export const ARCHIVE_RECEIVER_TYPE =
  /^(?:Zip|Jar|Tar|Cpio|Ar|SevenZ|Archive)\w*(?:File|Stream|Reader)?$/;
export const ARCHIVE_RECEIVER_NAME = /zip|jar|tar|archive|zis|zf\b/i;
/** Calls on an archive that give its entries. */
export const ARCHIVE_ENTRIES = new Set(["entries", "getEntries", "stream", "getFileHeaders"]);
/** Methods of a `File` or `Path` value (Java and Kotlin) that read, write or change what it names. */
export const FILE_METHODS = new Set([
  "delete",
  "deleteOnExit",
  "mkdir",
  "mkdirs",
  "createNewFile",
  "renameTo",
  "list",
  "listFiles",
  "readText",
  "readBytes",
  "readLines",
  "writeText",
  "writeBytes",
  "appendText",
  "appendBytes",
  "inputStream",
  "outputStream",
  "bufferedReader",
  "bufferedWriter",
  "reader",
  "writer",
  "printWriter",
  "forEachLine",
  "useLines",
  "deleteRecursively",
  "copyTo",
  "copyRecursively",
  "walk",
  "walkTopDown",
  "walkBottomUp",
  "setLastModified",
  "setReadable",
  "setWritable",
  "setExecutable",
]);
/** Conversions of a path value that keep it (the same file by another name). */
export const PATH_KEEPERS = new Set([
  "toPath",
  "toFile",
  "getAbsoluteFile",
  "getAbsolutePath",
  "getCanonicalFile",
  "getCanonicalPath",
  "getPath",
  "toAbsolutePath",
  "normalize",
  "toRealPath",
  "getParentFile",
  "getParent",
  "toString",
  "toUri",
  "absoluteFile",
  "absolutePath",
  "canonicalFile",
  "canonicalPath",
  "path",
  "parentFile",
  "parent",
]);
/** Of those, the ones that resolve `..` and links, so a prefix test on the result means something. */
export const CANONICALIZERS = new Set([
  "normalize",
  "toRealPath",
  "getCanonicalFile",
  "getCanonicalPath",
  "canonicalFile",
  "canonicalPath",
]);
/** Members of a path that give only its last element (`Path.getFileName()`, Kotlin `File.name`). */
export const LAST_ELEMENT = new Set([
  "getFileName",
  "fileName",
  "getName",
  "name",
  "nameWithoutExtension",
]);
/** Methods of an upload or request part that give the file name the client chose. */
export const CLIENT_FILE_NAMES = new Set([
  "getOriginalFilename",
  "getSubmittedFileName",
  "originalFileName",
  "originalFilename",
]);
/** A receiver of `resolve(...)` that is a path by its usual name. */
export const PATH_NAME = /path|dir|folder|root|base|file|upload|target|dest|home|location/i;
/**
 * Why a value is "probably fine" when the reason is only that it is a number, a UUID, a boolean
 * or a constant-style name from another file: alone, as the whole value, that is not worth a finding.
 */
export const BENIGN_BARE =
  /number|numeric|boolean|enum type|arithmetic|cast to|constant-style name/;

/** Text of a skipped code form that makes it matter: a call that runs a process or opens a file. */
export const OS_CALL_TEXT =
  /\b(?:exec|ProcessBuilder|CommandLine|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile|File|Paths|Path|Files|FileUtils|getRealPath|FileSystemResource)\s*[.(]/;
