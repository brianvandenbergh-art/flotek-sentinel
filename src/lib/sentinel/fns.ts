import { createServerFn } from "@tanstack/react-start";
import { authMiddleware } from "@/lib/auth/middleware";

export const getConsole = createServerFn({ method: "GET" })
  .middleware([authMiddleware])
  .handler(async ({ context }) => {
    const { loadConsole } = await import("./data.server");
    return loadConsole(context.userId);
  });

export const runChecks = createServerFn({ method: "POST" })
  .middleware([authMiddleware])
  .handler(async ({ context }) => {
    const { runDueChecks } = await import("./data.server");
    return runDueChecks(context.userId);
  });

export const createMonitor = createServerFn({ method: "POST" })
  .middleware([authMiddleware])
  .validator((input: { kind: "website" | "domain"; target: string; name?: string; keyword?: string }) => input)
  .handler(async ({ context, data }) => {
    const { addMonitor } = await import("./data.server");
    return addMonitor(context.userId, data);
  });

export const pauseMonitor = createServerFn({ method: "POST" })
  .middleware([authMiddleware])
  .validator((input: { id: string; paused: boolean }) => input)
  .handler(async ({ context, data }) => {
    const { setPaused } = await import("./data.server");
    return setPaused(context.userId, data.id, data.paused);
  });

export const deleteMonitor = createServerFn({ method: "POST" })
  .middleware([authMiddleware])
  .validator((input: { id: string }) => input)
  .handler(async ({ context, data }) => {
    const { removeMonitor } = await import("./data.server");
    return removeMonitor(context.userId, data.id);
  });

export const rescanMonitor = createServerFn({ method: "POST" })
  .middleware([authMiddleware])
  .validator((input: { id: string }) => input)
  .handler(async ({ context, data }) => {
    const { rescan } = await import("./data.server");
    return rescan(context.userId, data.id);
  });

export const setIncident = createServerFn({ method: "POST" })
  .middleware([authMiddleware])
  .validator((input: { id: string; archived: boolean }) => input)
  .handler(async ({ context, data }) => {
    const { acknowledge } = await import("./data.server");
    return acknowledge(context.userId, data.id, data.archived);
  });

export const manageTeam = createServerFn({ method: "POST" })
  .middleware([authMiddleware])
  .validator((input: { action: "create" | "remove" | "role" | "password"; payload: Record<string, string> }) => input)
  .handler(async ({ context, data }) => {
    const { teamAction } = await import("./data.server");
    return teamAction(context.userId, data.action, data.payload);
  });

export const runWordpress = createServerFn({ method: "POST" })
  .middleware([authMiddleware])
  .validator((input: { id: string; action: string; payload?: Record<string, string> }) => input)
  .handler(async ({ context, data }) => {
    const { wordpressAction } = await import("./data.server");
    return wordpressAction(context.userId, data.id, data.action, data.payload || {});
  });

export const siteReport = createServerFn({ method: "POST" })
  .middleware([authMiddleware])
  .validator((input: { id: string }) => input)
  .handler(async ({ context, data }) => {
    const { buildReport } = await import("./data.server");
    return buildReport(context.userId, data.id);
  });
