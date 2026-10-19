import { createFileRoute } from "@tanstack/react-router";
import { auth } from "@/lib/auth/server";

const attempts = new Map<string, { n: number; reset: number }>();

function bump(key: string) {
  const now = Date.now();
  const slot = attempts.get(key);
  if (!slot || slot.reset < now) {
    attempts.set(key, { n: 1, reset: now + 10 * 60 * 1000 });
    return;
  }
  slot.n += 1;
}

export const Route = createFileRoute("/api/sentinel/login")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        let body: { identifier?: string; password?: string } = {};
        try {
          body = (await request.json()) as { identifier?: string; password?: string };
        } catch {
          return Response.json({ error: "Invalid request" }, { status: 400 });
        }
        const identifier = String(body.identifier || "").trim().toLowerCase().slice(0, 120);
        const password = String(body.password || "");
        const now = Date.now();
        const slot = attempts.get(identifier);
        if (slot && slot.reset > now && slot.n >= 8) {
          return Response.json({ error: "Too many attempts. Wait a few minutes and try again." }, { status: 429 });
        }
        const { findLoginEmail } = await import("@/lib/sentinel/bootstrap.server");
        const email = identifier ? await findLoginEmail(identifier) : null;
        if (!email || !password) {
          bump(identifier || "blank");
          return Response.json({ error: "The username or password is not correct." }, { status: 401 });
        }
        try {
          return await auth.api.signInEmail({
            body: { email, password },
            headers: request.headers,
            asResponse: true,
          });
        } catch {
          bump(identifier);
          return Response.json({ error: "The username or password is not correct." }, { status: 401 });
        }
      },
    },
  },
});
