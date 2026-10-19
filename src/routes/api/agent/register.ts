import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/api/agent/register")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        try {
          const { registerFromAgent } = await import("@/lib/sentinel/data.server");
          const secret = request.headers.get("x-hub-secret") || "";
          const body = (await request.json()) as Record<string, unknown>;
          const result = await registerFromAgent(secret, body);
          return Response.json({ success: true, ...result });
        } catch (error) {
          const status = (error as { status?: number }).status || 400;
          return Response.json({ success: false, error: error instanceof Error ? error.message : "Rejected" }, { status });
        }
      },
    },
  },
});
