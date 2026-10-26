// corpus: expect=none
export async function encrypt(key: CryptoKey, data: Uint8Array) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  return crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
}
