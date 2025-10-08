"use client"

import type React from "react"
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react"
import {
  createVault as createVaultLib,
  unlockVault as unlockVaultLib,
  savePassword as savePasswordLib,
  getPassword as getPasswordLib,
  isInitialized as isInitializedLib,
} from "@/lib/vault"

type VaultContextType = {
  unlocked: boolean
  initializing: boolean
  masterHint: string | null
  createVault: (masterPassword: string) => Promise<boolean>
  unlockVault: (masterPassword: string) => Promise<boolean>
  savePassword: (service: string, username: string, password: string) => Promise<{ ok: boolean; message?: string }>
  getPassword: (service: string, username: string) => Promise<string | null>
}

const VaultContext = createContext<VaultContextType | null>(null)

export function VaultProvider({ children }: { children: React.ReactNode }) {
  const [unlocked, setUnlocked] = useState(false)
  const [initializing, setInitializing] = useState(true)

  useEffect(() => {
    // Determine if a vault exists; we don't auto-unlock
    setInitializing(false)
  }, [])

  const createVault = useCallback(async (masterPassword: string) => {
    const ok = await createVaultLib(masterPassword)
    setUnlocked(ok)
    return ok
  }, [])

  const unlockVault = useCallback(async (masterPassword: string) => {
    const ok = await unlockVaultLib(masterPassword)
    setUnlocked(ok)
    return ok
  }, [])

  const savePassword = useCallback(async (service: string, username: string, password: string) => {
    const res = await savePasswordLib(service, username, password)
    return res
  }, [])

  const getPassword = useCallback(async (service: string, username: string) => {
    return getPasswordLib(service, username)
  }, [])

  const value = useMemo<VaultContextType>(
    () => ({
      unlocked,
      initializing,
      masterHint: isInitializedLib() ? "Vault exists. Unlock to use." : null,
      createVault,
      unlockVault,
      savePassword,
      getPassword,
    }),
    [unlocked, initializing, createVault, unlockVault, savePassword, getPassword],
  )

  return <VaultContext.Provider value={value}>{children}</VaultContext.Provider>
}

export function useVault() {
  const ctx = useContext(VaultContext)
  if (!ctx) throw new Error("useVault must be used within VaultProvider")
  return ctx
}
