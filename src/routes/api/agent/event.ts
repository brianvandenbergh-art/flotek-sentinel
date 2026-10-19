import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/api/agent/event")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        try {
          const { recordAgentEvent } = await import("@/lib/sentinel/data.server");
          const secret = request.headers.get("x-hub-secret") || "";
          const body = (await request.json()) as Record<string, unknown>;
          await recordAgentEvent(secret, body);
          return Response.json({ success: true });
        } catch (error) {
          return Response.json(
            { success: false, error: error instanceof Error ? error.message : "Rejected" },
            { status: 403 },
          );
        }
      },
    },
  },
});
