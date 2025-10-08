"use client"

import { useMemo, useState } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectTrigger, SelectContent, SelectItem, SelectValue } from "@/components/ui/select"
import { generateAlternatives, THEMES } from "@/lib/password-eval"

export default function PasswordSuggestions() {
  const [theme, setTheme] = useState<string>("none")
  const [count, setCount] = useState<string>("3")

  const suggestions = useMemo(() => {
    const t = theme === "none" ? undefined : theme
    return generateAlternatives(t, Number(count) || 3)
  }, [theme, count])

  function copy(text: string) {
    navigator.clipboard.writeText(text).then(() => {
      // Optional toast if desired; keeping minimal per brief
    })
  }

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div>
          <label className="text-sm font-medium">Theme</label>
          <Select value={theme} onValueChange={setTheme}>
            <SelectTrigger className="w-full mt-1">
              <SelectValue placeholder="Theme" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="none">None</SelectItem>
              {THEMES.map((t) => (
                <SelectItem key={t} value={t}>
                  {t}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div>
          <label className="text-sm font-medium">Count</label>
          <Input className="mt-1" value={count} onChange={(e) => setCount(e.target.value)} />
        </div>
        <div className="flex items-end">
          <Button
            onClick={() => {
              /* re-compute via state deps */
            }}
          >
            Refresh
          </Button>
        </div>
      </div>

      <div className="space-y-2">
        {suggestions.map((s, i) => (
          <div key={i} className="flex items-center justify-between rounded-md border p-2">
            <span className="font-mono text-sm">{s}</span>
            <Button size="sm" variant="secondary" onClick={() => copy(s)}>
              Copy
            </Button>
          </div>
        ))}
      </div>
    </div>
  )
}
