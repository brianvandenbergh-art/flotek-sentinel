import { useState, type FormEvent } from "react";
import { createFileRoute, Navigate } from "@tanstack/react-router";
import { useCurrentUserState } from "@/lib/auth/use-current-user";

export const Route = createFileRoute("/login")({ component: Login });

function Login() {
  const { user, isPending } = useCurrentUserState();
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  if (isPending) return <ScreenSkeleton />;
  if (user) return <Navigate to="/" />;

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const response = await fetch("/api/sentinel/login", {
        method: "POST",
        credentials: "include",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ identifier, password }),
      });
      const data = (await response.json().catch(() => ({}))) as { error?: string; token?: string };
      if (!response.ok) {
        setError(data.error || "Sign-in failed.");
        setBusy(false);
        return;
      }
      const token = response.headers.get("set-auth-token") || data.token;
      if (token) window.sessionStorage.setItem("grok-auth.bearer-token", token);
      window.location.assign("/");
    } catch {
      setError("Sign-in failed. Try again.");
      setBusy(false);
    }
  }

  return (
    <main className="grid min-h-screen place-items-center bg-bg px-4 py-10">
      <div className="w-full max-w-md">
        <div className="mb-8 flex justify-center">
          <img src="/brand/flotek-logo.svg" alt="Flotek group" className="h-8 w-auto" />
        </div>
        <form onSubmit={submit} className="rounded-card border border-line bg-surface p-6 shadow-sm sm:p-8">
          <p className="text-sm font-semibold tracking-wide text-plum">Sentinel</p>
          <h1 className="mt-1 text-2xl font-semibold text-ink">Sign in</h1>
          <p className="mt-2 text-sm leading-6 text-muted">
            Website and domain monitoring for the Flotek team. Accounts are issued by an administrator.
          </p>
          <label className="mt-6 block text-sm font-medium text-ink" htmlFor="username">
            Username
          </label>
          <input
            id="username"
            name="username"
            autoComplete="username"
            value={identifier}
            onChange={(event) => setIdentifier(event.target.value)}
            className="mt-1.5 h-11 w-full rounded-xl border border-line bg-bg px-3 text-sm text-ink"
            required
          />
          <label className="mt-4 block text-sm font-medium text-ink" htmlFor="password">
            Password
          </label>
          <input
            id="password"
            name="password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            className="mt-1.5 h-11 w-full rounded-xl border border-line bg-bg px-3 text-sm text-ink"
            required
          />
          {error ? <p className="mt-4 text-sm text-down">{error}</p> : null}
          <button
            type="submit"
            disabled={busy}
            className="mt-6 h-11 w-full rounded-full bg-orange text-sm font-semibold text-white hover:bg-orange-deep disabled:opacity-60"
          >
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </form>
      </div>
    </main>
  );
}

function ScreenSkeleton() {
  return <main className="min-h-screen bg-bg" />;
}
