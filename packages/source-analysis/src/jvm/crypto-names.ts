/** Names the Java and Kotlin cryptography rules (PG-CRYPTO-001/002/003, PG-AUTH-001) look for. */

/** Text of a skipped code form that makes it matter: a call of the cryptography rules. */
export const CRYPTO_CALL_TEXT =
  /\b(?:MessageDigest|SecretKeySpec|IvParameterSpec|GCMParameterSpec|Cipher|DigestUtils|Hashing|hmacShaKeyFor|signWith|setSigningKey|setCipherKey|HMAC(?:256|384|512)|MACSigner|MACVerifier|RandomStringUtils|NoOpPasswordEncoder|StandardPasswordEncoder|LdapShaPasswordEncoder|MessageDigestPasswordEncoder|Md4PasswordEncoder)\b/;

/** Imported cryptography libraries with their own APIs that these rules do not read. */
export const UNSUPPORTED_CRYPTO_LIBRARIES: ReadonlyArray<{ prefix: string; label: string }> = [
  { prefix: "org.bouncycastle", label: "Bouncy Castle" },
  { prefix: "com.google.crypto.tink", label: "Google Tink" },
  { prefix: "org.jasypt", label: "Jasypt" },
  { prefix: "org.apache.shiro.crypto", label: "Apache Shiro crypto" },
];

/** Import paths of a library that only register a JCA provider: calls through the JCA are still read. */
const PROVIDER_ONLY = ["org.bouncycastle.jce.provider", "org.bouncycastle.jcajce.provider"];

/** The unsupported cryptography libraries a file imports, by label. */
export function unsupportedCryptoLibraries(imports: readonly string[]): string[] {
  const labels = new Set<string>();
  for (const library of UNSUPPORTED_CRYPTO_LIBRARIES) {
    const hit = imports.some(
      (name) =>
        (name === library.prefix || name.startsWith(`${library.prefix}.`)) &&
        !PROVIDER_ONLY.some((only) => name === only || name.startsWith(`${only}.`)),
    );
    if (hit) labels.add(library.label);
  }
  return [...labels];
}

/** A cipher that is broken or deprecated whatever the mode. */
const WEAK_CIPHER_NAME =
  /^(?:DES|DESede|TripleDES|3DES|TDEA|RC2|RC4|ARCFOUR|ARC4|Blowfish|BF|IDEA|SKIPJACK|CAST5|CAST-?128)$/i;
const WEAK_PBE = /^PBEWith\w*?And(?:DES|DESede|TripleDES|RC2|RC4)/i;

/**
 * Why a JCA transformation or algorithm name is weak, or null. `transformation` is true for
 * `Cipher.getInstance` text, where a bare `AES` means ECB and `/ECB/` is a block mode; for a key
 * algorithm (`SecretKeySpec`, `KeyGenerator`) only the cipher name counts.
 */
export function weakCipherReason(text: string, transformation: boolean): string | null {
  const parts = text.split("/").map((part) => part.trim());
  const algorithm = parts[0] ?? "";
  const mode = parts[1]?.toUpperCase();
  if (WEAK_CIPHER_NAME.test(algorithm)) return `${algorithm} cipher`;
  if (WEAK_PBE.test(algorithm)) return `${algorithm} password-based cipher`;
  if (!transformation) return null;
  if (/^AES(?:_\d+)?$/i.test(algorithm)) {
    if (parts.length === 1) return "AES with no mode (the default is ECB)";
    if (mode === "ECB") return "AES in ECB mode";
  }
  if (mode === "ECB" && !/^(?:RSA|ECIES)/i.test(algorithm)) return `${algorithm} in ECB mode`;
  return null;
}

/** MD5, SHA-1 and the older digests. `SHA` alone is SHA-1 in the JCA. */
export const WEAK_DIGEST = /^(?:MD2|MD4|MD5|SHA-?1|SHA)$/i;

/** Commons Codec and Spring `DigestUtils` helpers of the weak digests, and what they are. */
export const WEAK_DIGEST_HELPERS = new Map<string, string>([
  ["md5Hex", "MD5"],
  ["md5", "MD5"],
  ["md5DigestAsHex", "MD5"],
  ["md5Digest", "MD5"],
  ["md2Hex", "MD2"],
  ["md2", "MD2"],
  ["sha1Hex", "SHA-1"],
  ["sha1", "SHA-1"],
  ["shaHex", "SHA-1"],
  ["sha", "SHA-1"],
]);

/** `DigestUtils` helpers that give a weak `MessageDigest` object. */
export const WEAK_DIGEST_GETTERS = new Map<string, string>([
  ["getMd5Digest", "MD5"],
  ["getSha1Digest", "SHA-1"],
  ["getShaDigest", "SHA-1"],
]);

/** `MessageDigestAlgorithms.MD5` and `.SHA_1` (Commons Codec). */
export const DIGEST_CONSTANTS = new Map<string, string>([
  ["MD2", "MD2"],
  ["MD5", "MD5"],
  ["SHA_1", "SHA-1"],
]);

/** A name that stands for a password. Split into words, so `bypassCheck` is not one. */
export function isPasswordWord(name: string): boolean {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .split(/[^A-Za-z0-9]+/)
    .some((word) => /^(?:password|passwd|pwd|pass|passphrase|passcode)$/i.test(word));
}

/** The names the password-storage rule accepts for a value that is a plain password (as in JS). */
export const PASSWORD_NAME =
  /^(?:password|passwd|pwd|pass|(?:user|new|plain|raw|clear|plaintext|cleartext)Password)$/i;

/** A call that hashes: a password hashing function or an encoder. */
export const HASH_CALL =
  /^(?:encode|encodePassword|hashpw|hashPassword|hash|hashToString|bcrypt|argon2|scrypt|pbkdf2|digest|crypt|sha\d*Hex|md5Hex|hashString)$/i;
/** Deprecated Spring Security password encoders (fast or unsalted hashes). */
export const WEAK_PASSWORD_ENCODERS = new Set([
  "StandardPasswordEncoder",
  "LdapShaPasswordEncoder",
  "MessageDigestPasswordEncoder",
  "Md4PasswordEncoder",
  "Md5PasswordEncoder",
  "ShaPasswordEncoder",
]);
export const HASH_OWNER = /bcrypt|argon2|scrypt|pbkdf2|passwordEncoder|encoder|hasher/i;
export const HASH_TYPE = /Encoder|BCrypt|Argon2|SCrypt|Pbkdf2|Hasher/;

/** Names that mean a value is a key, IV, salt, token, nonce or password-reset secret. */
export function isSecretContextName(name: string): boolean {
  if (/token|nonce|salt|otp|csrf|xsrf|passw(?:or)?d|passcode|passphrase|secret|apikey/i.test(name))
    return true;
  if (/(?:reset|verif\w*|confirm\w*|activation|invite|session)(?:code|key|id|link)/i.test(name))
    return true;
  if (
    /^iv$|^iv[A-Z_0-9]|[a-z0-9_]IV$|[a-z0-9]Iv$|_iv(?:_|$)|initVector|initializationVector/.test(
      name,
    )
  )
    return true;
  return /(?:secret|crypto|encryption|aes|hmac|signing|private)Key|^key(?:Bytes)?$|^keyMaterial$/i.test(
    name,
  );
}

/** Methods of `java.util.Random` and friends that give a value. */
export const RANDOM_METHODS =
  /^(?:next|nextInt|nextLong|nextDouble|nextFloat|nextBoolean|nextGaussian|nextBytes|nextUInt|nextULong|nextUBytes|ints|longs|doubles)$/;

/** Calls that fill or overwrite the byte array they are given. */
export const FILLS_ARGUMENT =
  /^(?:nextBytes|read|readFully|readNBytes|arraycopy|fill|get|setAll|copyInto|shuffle|reverse|sort|generateSeed|nextUBytes)$/;

/** Request-DTO parameter annotations and type-name suffixes. */
export const REQUEST_PARAM_ANNOTATIONS = new Set([
  "RequestBody",
  "ModelAttribute",
  "Valid",
  "Validated",
  "RequestParam",
  "RequestPart",
  "FormParam",
  "QueryParam",
  "BeanParam",
]);
export const STRONG_REQUEST_TYPE =
  /(?:Request|Req|Form|Payload|Body|Command|Cmd|Signup|SignUp|Register|Registration)$/;
export const DTO_TYPE = /(?:Dto|DTO)$/;

/** Persisting calls (a repository, a mapper, an entity manager). */
export const PERSIST_CALLS = new Set([
  "save",
  "saveAll",
  "saveAndFlush",
  "persist",
  "merge",
  "insert",
  "insertSelective",
  "insertOrUpdate",
  "upsert",
  "updateById",
  "create",
  "update",
]);
export const REPOSITORY_NAME = /(?:repo|repository|dao|mapper|store|jpa|manager)$/i;
export const JDBC_UPDATE_CALLS = new Set(["update", "batchUpdate", "execute", "executeUpdate"]);
