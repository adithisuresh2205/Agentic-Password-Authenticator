"use client"

import { useMemo, useState, useEffect } from "react"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { getPasswordFeatures, getPasswordScore, explanationsFor } from "@/lib/password-eval"
import { useVault } from "./vault-context"
import useSWR from "swr"
import { DATASET_URL, setLeakedWords } from "@/lib/password-eval"

export default function PasswordLiveCheck() {
  const [password, setPassword] = useState("")
  const [saving, setSaving] = useState(false)
  const { unlocked, savePassword } = useVault()

  // load leaked dataset once
  const { data: leakCSV } = useSWR("leaked-dataset", async () => {
    const r = await fetch(DATASET_URL, { cache: "force-cache" })
    return r.ok ? r.text() : ""
  })

  useEffect(() => {
    if (!leakCSV) return
    // simple CSV parser: expects header "text,category"
    const lines = leakCSV.split(/\r?\n/).filter(Boolean)
    const header = lines.shift() || ""
    const textIdx = header.toLowerCase().split(",").indexOf("text")
    const catIdx = header.toLowerCase().split(",").indexOf("category")
    const set = new Set<string>()
    for (const line of lines) {
      const cols = line.split(",")
      const text = cols[textIdx]?.trim()
      const cat = cols[catIdx]?.trim()
      if (text && cat === "1") set.add(text)
    }
    setLeakedWords(set)
  }, [leakCSV])

  const features = useMemo(() => getPasswordFeatures(password), [password])
  const { score, breachProb } = useMemo(() => getPasswordScore(features), [features])
  const allowed = score >= 70 && !features.isLeaked

  const strengthTone = score >= 90 ? "success" : score >= 70 ? "secondary" : "destructive"

  async function onSave() {
    if (!unlocked) return
    setSaving(true)
    const service = prompt("Enter service name (e.g., Google):")?.trim() || ""
    const username = prompt("Enter username:")?.trim() || ""
    if (!service || !username) {
      setSaving(false)
      return
    }
    const res = await savePassword(service, username, password)
    setSaving(false)
    alert(res.ok ? `Saved for ${service}` : res.message || "Save failed")
  }

  const hints = explanationsFor(features)

  return (
    <div className="space-y-4">
      <label className="text-sm font-medium">Password</label>
      <Input
        type="password"
        placeholder="Type to check..."
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />

      <div className="flex items-center gap-3">
        <Badge variant={strengthTone as any} aria-label={`Score ${score} out of 100`}>
          Score: {score}/100
        </Badge>
        <Badge variant="outline" aria-label="Estimated breach probability">
          {"Breach p≈ "}
          {breachProb.toFixed(2)}
        </Badge>
        <Badge variant={allowed ? "default" : "destructive"} aria-label={allowed ? "Allowed" : "Denied"}>
          {allowed ? "Allowed" : "Denied"}
        </Badge>
        <Badge variant="outline" aria-label="Leaked dataset loaded">
          Leaks DB: {leakCSV ? "on" : "off"}
        </Badge>
      </div>

      <ul className="list-disc pl-6 text-sm text-muted-foreground">
        {hints.map((h, i) => (
          <li key={i}>{h}</li>
        ))}
      </ul>

      <div className="flex gap-2">
        <Button disabled={!unlocked || !allowed || !password || saving} onClick={onSave}>
          {saving ? "Saving..." : "Save to Vault"}
        </Button>
      </div>
    </div>
  )
}
