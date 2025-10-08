"use client"

import { useState } from "react"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Label } from "@/components/ui/label"
import { useVault } from "./vault-context"
import { isInitialized } from "@/lib/vault"

export default function VaultPanel() {
  const { unlocked, createVault, unlockVault, getPassword } = useVault()
  const [master, setMaster] = useState("")
  const [service, setService] = useState("")
  const [username, setUsername] = useState("")
  const [retrieved, setRetrieved] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  async function onCreate() {
    setLoading(true)
    const ok = await createVault(master)
    setLoading(false)
    alert(ok ? "Vault created and unlocked." : "Failed to create vault.")
  }

  async function onUnlock() {
    setLoading(true)
    const ok = await unlockVault(master)
    setLoading(false)
    alert(ok ? "Vault unlocked." : "Incorrect master password or corrupted vault.")
  }

  async function onView() {
    setRetrieved(null)
    const val = await getPassword(service, username)
    setRetrieved(val)
  }

  const thereIsVault = isInitialized()

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="md:col-span-2">
          <Label htmlFor="master">Master Password</Label>
          <Input
            id="master"
            type="password"
            value={master}
            onChange={(e) => setMaster(e.target.value)}
            placeholder={thereIsVault ? "Enter to unlock" : "Create a new one"}
            className="mt-1"
          />
        </div>
        <div className="flex items-end gap-2">
          {!thereIsVault ? (
            <Button onClick={onCreate} disabled={!master || loading}>
              {loading ? "Working..." : "Create Vault"}
            </Button>
          ) : (
            <Button onClick={onUnlock} disabled={!master || unlocked || loading}>
              {loading ? "Working..." : unlocked ? "Unlocked" : "Unlock"}
            </Button>
          )}
        </div>
      </div>

      <div className="rounded-md border p-4 space-y-3">
        <h3 className="font-medium">View a Saved Password</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div>
            <Label htmlFor="service">Service</Label>
            <Input id="service" value={service} onChange={(e) => setService(e.target.value)} className="mt-1" />
          </div>
          <div>
            <Label htmlFor="username">Username</Label>
            <Input id="username" value={username} onChange={(e) => setUsername(e.target.value)} className="mt-1" />
          </div>
          <div className="flex items-end">
            <Button onClick={onView} disabled={!unlocked || !service || !username}>
              View
            </Button>
          </div>
        </div>
        {retrieved !== null && (
          <p className="text-sm">
            <span className="font-medium">Password:</span>{" "}
            <span className="font-mono">{retrieved || "(not found)"}</span>
          </p>
        )}
      </div>

      <p className="text-sm text-muted-foreground">
        Data is stored locally in your browser and encrypted with your master password.
      </p>
    </div>
  )
}
