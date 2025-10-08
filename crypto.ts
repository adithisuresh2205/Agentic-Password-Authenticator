const TEXT = new TextEncoder()
const RTEXT = new TextDecoder()

export function randomBytes(len: number): Uint8Array {
  const b = new Uint8Array(len)
  crypto.getRandomValues(b)
  return b
}

export async function sha256Hex(data: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", data)
  return bufferToHex(digest)
}

export async function deriveKey(masterPassword: string, salt: Uint8Array): Promise<CryptoKey> {
  const baseKey = await crypto.subtle.importKey("raw", TEXT.encode(masterPassword), { name: "PBKDF2" }, false, [
    "deriveKey",
  ])
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 480_000, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  )
}

export async function encryptJSON(obj: unknown, key: CryptoKey): Promise<string> {
  const iv = randomBytes(12)
  const data = TEXT.encode(JSON.stringify(obj))
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data)
  return `${bytesToBase64(iv)}:${bytesToBase64(new Uint8Array(ct))}`
}

export async function decryptJSON<T = unknown>(payload: string, key: CryptoKey): Promise<T> {
  const [ivB64, ctB64] = payload.split(":")
  const iv = base64ToBytes(ivB64)
  const ct = base64ToBytes(ctB64)
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct)
  return JSON.parse(RTEXT.decode(new Uint8Array(pt))) as T
}

export async function encryptText(plain: string, key: CryptoKey): Promise<string> {
  const iv = randomBytes(12)
  const data = new TextEncoder().encode(plain)
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data)
  return `${bytesToBase64(iv)}:${bytesToBase64(new Uint8Array(ct))}`
}

export async function decryptText(payload: string, key: CryptoKey): Promise<string> {
  const [ivB64, ctB64] = payload.split(":")
  const iv = base64ToBytes(ivB64)
  const ct = base64ToBytes(ctB64)
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct)
  return new TextDecoder().decode(new Uint8Array(pt))
}

export function bytesToBase64(bytes: Uint8Array): string {
  let bin = ""
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i])
  return btoa(bin)
}

export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

function bufferToHex(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf)
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
}
