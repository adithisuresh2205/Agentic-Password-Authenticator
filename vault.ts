import {
  base64ToBytes,
  bytesToBase64,
  deriveKey,
  encryptJSON,
  decryptJSON,
  randomBytes,
  sha256Hex,
  encryptText,
  decryptText,
} from "./crypto"

const STORAGE_KEY = "pass_vault"

type VaultInner = {
  passwords: Record<string, Record<string, string>> // service -> username -> encryptedPassword
  password_hashes: string[]
}

type VaultStored = {
  vault_salt: string
  hash_salt: string
  encrypted_data: string
}

let cachedKey: CryptoKey | null = null
let cachedInner: VaultInner | null = null
let cachedHashSalt: Uint8Array | null = null
let cachedVaultSalt: Uint8Array | null = null

export function isInitialized(): boolean {
  if (typeof window === "undefined") return false
  return !!localStorage.getItem(STORAGE_KEY)
}

export async function createVault(masterPassword: string): Promise<boolean> {
  try {
    const vault_salt = randomBytes(16)
    const hash_salt = randomBytes(16)
    const key = await deriveKey(masterPassword, vault_salt)

    const inner: VaultInner = {
      passwords: {},
      password_hashes: [],
    }

    const encrypted_data = await encryptJSON(inner, key)
    const stored: VaultStored = {
      vault_salt: bytesToBase64(vault_salt),
      hash_salt: bytesToBase64(hash_salt),
      encrypted_data,
    }
    localStorage.setItem(STORAGE_KEY, JSON.stringify(stored))
    cachedKey = key
    cachedInner = inner
    cachedHashSalt = hash_salt
    cachedVaultSalt = vault_salt
    return true
  } catch {
    return false
  }
}

export async function unlockVault(masterPassword: string): Promise<boolean> {
  try {
    const stored = getStored()
    if (!stored) return false
    const vaultSalt = base64ToBytes(stored.vault_salt)
    const key = await deriveKey(masterPassword, vaultSalt)
    const inner = await decryptJSON<VaultInner>(stored.encrypted_data, key)
    cachedKey = key
    cachedInner = inner
    cachedHashSalt = base64ToBytes(stored.hash_salt)
    cachedVaultSalt = vaultSalt
    return true
  } catch {
    return false
  }
}

export async function savePassword(
  service: string,
  username: string,
  password: string,
): Promise<{ ok: boolean; message?: string }> {
  if (!cachedKey || !cachedInner || !cachedHashSalt) return { ok: false, message: "Vault is locked." }

  // enforce uniqueness across vault using salted sha256 hex
  const salted = new Uint8Array(cachedHashSalt.length + new TextEncoder().encode(password).length)
  salted.set(cachedHashSalt, 0)
  salted.set(new TextEncoder().encode(password), cachedHashSalt.length)
  const hash = await sha256Hex(salted)
  if (cachedInner.password_hashes.includes(hash)) {
    return { ok: false, message: "Save denied: password already used for another service." }
  }

  if (!cachedInner.passwords[service]) cachedInner.passwords[service] = {}
  const enc = await encryptText(password, cachedKey)
  cachedInner.passwords[service][username] = enc

  cachedInner.password_hashes.push(hash)
  await persist()
  return { ok: true }
}

export async function getPassword(service: string, username: string): Promise<string | null> {
  if (!cachedKey || !cachedInner) return null
  const entry = cachedInner.passwords[service]?.[username]
  if (!entry) return null
  try {
    if (entry.includes(":")) {
      return await decryptText(entry, cachedKey)
    }
    return entry
  } catch {
    return entry
  }
}

async function persist() {
  if (!cachedKey || !cachedInner || !cachedHashSalt || !cachedVaultSalt) return
  const encrypted_data = await encryptJSON(cachedInner, cachedKey)
  const stored: VaultStored = {
    vault_salt: bytesToBase64(cachedVaultSalt),
    hash_salt: bytesToBase64(cachedHashSalt),
    encrypted_data,
  }
  localStorage.setItem(STORAGE_KEY, JSON.stringify(stored))
}

function getStored(): VaultStored | null {
  if (typeof window === "undefined") return null
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    return raw ? (JSON.parse(raw) as VaultStored) : null
  } catch {
    return null
  }
}
