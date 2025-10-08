"use client"

import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card"
import { Separator } from "@/components/ui/separator"
import { VaultProvider } from "@/components/vault-context"
import PasswordLiveCheck from "@/components/password-live-check"
import PasswordSuggestions from "@/components/password-suggestions"
import VaultPanel from "@/components/vault-panel"

export default function HomePage() {
  return (
    <VaultProvider>
      <main className="container mx-auto max-w-5xl px-4 py-8">
        <header className="mb-8">
          <h1 className="text-3xl md:text-4xl font-semibold text-balance">Agentic Password Manager</h1>
          <p className="text-muted-foreground mt-2">
            Live password auditing, strong suggestions, and a local encrypted vault.
          </p>
        </header>

        <section className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <Card>
            <CardHeader>
              <CardTitle className="text-pretty">Live Password Check</CardTitle>
            </CardHeader>
            <CardContent>
              <PasswordLiveCheck />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-pretty">Generate Suggestions</CardTitle>
            </CardHeader>
            <CardContent>
              <PasswordSuggestions />
            </CardContent>
          </Card>
        </section>

        <Separator className="my-8" />

        <section>
          <Card>
            <CardHeader>
              <CardTitle className="text-pretty">Encrypted Vault</CardTitle>
            </CardHeader>
            <CardContent>
              <VaultPanel />
            </CardContent>
          </Card>
        </section>
      </main>
    </VaultProvider>
  )
}
