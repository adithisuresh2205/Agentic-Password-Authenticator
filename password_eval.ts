const keyboardWalks = ["qwert", "asdfg", "zxcvb", "123456", "password", "qwerty", "asdfgh", "abcdef"]
const commonWords = new Set(["password", "admin", "123456", "welcome", "secure", "football", "test", "love"])
const leetMap: Record<string, string> = { a: "4", e: "3", i: "1", o: "0", s: "5", t: "7" }

export type Features = {
  length: number
  hasUpper: boolean
  hasLower: boolean
  hasDigit: boolean
  hasSymbol: boolean
  isCommonWord: boolean
  isKeyboardWalk: boolean
  hasYearSuffix: boolean
  isLeaked: boolean // placeholder: false by default (no external API here)
  isSequence: boolean
  isLeetspeak: boolean
}

export const DATASET_URL =
  "https://raw.githubusercontent.com/shivamsolanki/10000-Most-Common-Passwords/main/Password.csv"

let LEAKED_WORDS: Set<string> | null = null

export function setLeakedWords(words: Set<string> | null) {
  LEAKED_WORDS = words
}

export function getPasswordFeatures(password: string): Features {
  const pw = password || ""
  const lower = pw.toLowerCase()

  const isSequence =
    /(\d)\1{2,}/.test(lower) ||
    /(.+)\1{2,}/.test(lower) ||
    lower.includes("123") ||
    lower.includes("321") ||
    lower.includes("abc") ||
    lower.includes("cba")

  const containsLeet = Object.entries(leetMap).some(([letter, sub]) => pw.includes(sub) && !lower.includes(letter))

  return {
    length: pw.length,
    hasUpper: /[A-Z]/.test(pw),
    hasLower: /[a-z]/.test(pw),
    hasDigit: /\d/.test(pw),
    hasSymbol: /[^\w\s]/.test(pw),
    isCommonWord: commonWords.has(lower),
    isKeyboardWalk: keyboardWalks.some((w) => lower.includes(w)),
    hasYearSuffix: /\d{2,4}$/.test(pw) && pw.length > 4,
    isLeaked: !!LEAKED_WORDS && LEAKED_WORDS.has(pw),
    isSequence: isSequence,
    isLeetspeak: containsLeet,
  }
}

// Lightweight heuristic “risk model” to approximate a breach probability and map to score
export function getPasswordScore(features: Features): { score: number; breachProb: number } {
  let score = 100

  if (features.length < 14) score -= Math.min(40, (14 - features.length) * 3)
  if (!(features.hasUpper && features.hasLower && features.hasDigit && features.hasSymbol)) score -= 20
  if (features.isCommonWord) score -= 30
  if (features.isKeyboardWalk) score -= 25
  if (features.hasYearSuffix) score -= 10
  if (features.isSequence) score -= 15
  if (features.isLeetspeak) score -= 10
  if (features.isLeaked) score = Math.min(score, 10)

  score = Math.max(0, Math.min(100, Math.round(score)))
  // Map inverse of score to an approximate probability (arbitrary monotonic mapping)
  const breachProb = 1 - score / 100
  return { score, breachProb }
}

export function explanationsFor(f: Features): string[] {
  const e: string[] = []
  if (f.isLeaked) e.push("🚨 Breach Alert: Known in past data breaches. Change immediately.")
  if (f.isCommonWord) e.push("👎 Common Word: Avoid very common words.")
  if (f.isKeyboardWalk) e.push("🚶 Predictable Pattern: Avoid common keyboard walks.")
  if (f.isSequence) e.push("🔢 Simple Sequence: Contains simple sequences of numbers/letters.")
  if (f.hasYearSuffix) e.push("📅 Year Suffix: Years are predictable, avoid them.")
  if (f.isLeetspeak) e.push("👀 Leetspeak: Simple substitutions are easy to reverse.")
  if (f.length < 14) e.push("📏 Too Short: Use 14+ characters.")
  if (!(f.hasSymbol && f.hasDigit && f.hasUpper))
    e.push("🔡 Low Variety: Mix uppercase, lowercase, numbers, and symbols.")
  if (e.length === 0) e.push("✅ Looks Great: No common weaknesses detected.")
  return e
}

// Suggestions
const wordlistBase = ["sky", "mango", "river", "blue", "tiger", "cloud", "ocean", "star", "jungle", "forest"]
const themedWordlists: Record<string, string[]> = {
  fantasy: ["dragon", "sword", "castle", "wizard", "potion", "elf", "knight", "dungeon"],
  "sci-fi": ["robot", "galaxy", "laser", "alien", "planet", "fusion", "quantum", "nebula"],
  travel: ["voyage", "summit", "journey", "horizon", "explore", "compass", "atlas", "wander"],
  food: ["cookie", "apple", "banana", "pizza", "sushi", "taco", "burger", "lemon"],
  animals: ["lion", "eagle", "whale", "panda", "bear", "wolf", "shark", "fox"],
}

export const THEMES = Object.keys(themedWordlists)

function sysRand<T>(arr: T[]): T {
  const idx = Math.floor((crypto.getRandomValues(new Uint32Array(1))[0] / 2 ** 32) * arr.length)
  return arr[Math.min(arr.length - 1, idx)]
}

function sample<T>(arr: T[], n: number): T[] {
  const res: T[] = []
  const used = new Set<number>()
  while (res.length < n && used.size < arr.length) {
    const i = Math.floor((crypto.getRandomValues(new Uint32Array(1))[0] / 2 ** 32) * arr.length)
    if (!used.has(i)) {
      used.add(i)
      res.push(arr[i])
    }
  }
  return res
}

export function generateSuggestion(theme?: string): string {
  const words =
    theme && themedWordlists[theme]
      ? sample(themedWordlists[theme], 2).concat(sysRand(wordlistBase))
      : sample(wordlistBase, 3)
  const digits = Array.from(crypto.getRandomValues(new Uint8Array(4)))
    .map((n) => (n % 10).toString())
    .join("")
  const symbols = "!@#$%^&*()_+-=[]{};:,./?"
  const symbol1 = symbols[Math.floor(Math.random() * symbols.length)]
  const symbol2 = symbols[Math.floor(Math.random() * symbols.length)]
  const separator = ["-", "_", "*"][Math.floor(Math.random() * 3)]
  const passphrase = `${capitalize(words[0])}${separator}${capitalize(words[1])}${symbol1}${capitalize(words[2])}${symbol2}${digits}`
  if (/(pass|word|123|abc)/i.test(passphrase)) return generateSuggestion(theme)
  return passphrase
}

export function generateAlternatives(theme?: string, n = 3): string[] {
  return Array.from({ length: n }, () => generateSuggestion(theme))
}

function capitalize(s: string) {
  return s.charAt(0).toUpperCase() + s.slice(1)
}
