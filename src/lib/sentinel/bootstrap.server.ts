import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { hashPassword, verifyPassword } from "better-auth/crypto";
import { getSql } from "@/lib/db";

/** Initial administrator. Password is hashed before it is stored. Rotate it after approval. */
const ADMIN_USERNAME = "flotek";
const ADMIN_EMAIL = "flotek@flotek.io";
const ADMIN_NAME = "Flotek";
const ADMIN_PASSWORD = process.env.FLOTEK_ADMIN_PASSWORD || "";

export type Role = "admin" | "operator" | "viewer";

export type Staff = {
  userId: string;
  email: string;
  username: string;
  name: string;
  role: Role;
};

type ProfileRow = {
  user_id: string;
  email: string;
  username: string;
  name: string;
  role: string;
};

function asStaff(row: ProfileRow): Staff {
  const role: Role =
    row.role === "admin" || row.role === "operator" || row.role === "viewer"
      ? row.role
      : "viewer";
  return {
    userId: row.user_id,
    email: row.email,
    username: row.username,
    name: row.name,
    role,
  };
}

export function normalizeUsername(value: string): string {
  return value.trim().toLowerCase();
}

export async function ensureSentinelReady(): Promise<void> {
  const sql = await getSql();
  const secret = await sql<{ value: string }>`select value from app_settings where key = 'hub_secret'`;
  if (!secret[0]) {
    const value = randomBytes(24).toString("hex");
    await sql`insert into app_settings (key, value) values ('hub_secret', ${value})`;
  }

  const existing = await sql<ProfileRow>`select user_id, email, username, name, role from staff_profiles where username = ${ADMIN_USERNAME}`;
  if (existing[0]) return;

  const authUser = await sql<{ id: string }>`select id from "user" where lower(email) = ${ADMIN_EMAIL}`;
  let userId = authUser[0]?.id;
  if (!userId) {
    userId = randomUUID();
    const now = new Date().toISOString();
    const hash = await hashPassword(ADMIN_PASSWORD);
    await sql`
      insert into "user" ("id", "name", "email", "emailVerified", "createdAt", "updatedAt")
      values (${userId}, ${ADMIN_NAME}, ${ADMIN_EMAIL}, true, ${now}, ${now})
    `;
    await sql`
      insert into "account" ("id", "accountId", "providerId", "userId", "password", "createdAt", "updatedAt")
      values (${randomUUID()}, ${userId}, 'credential', ${userId}, ${hash}, ${now}, ${now})
    `;
  }

  await sql`
    insert into staff_profiles (user_id, email, username, name, role)
    values (${userId}, ${ADMIN_EMAIL}, ${ADMIN_USERNAME}, ${ADMIN_NAME}, 'admin')
    on conflict (user_id) do nothing
  `;
}

export async function getStaff(userId: string): Promise<Staff | null> {
  await ensureSentinelReady();
  const sql = await getSql();
  const rows = await sql<ProfileRow>`
    select user_id, email, username, name, role from staff_profiles where user_id = ${userId}
  `;
  return rows[0] ? asStaff(rows[0]) : null;
}

export async function resolveStaff(user: {
  id: string;
  email?: string | null;
  name?: string | null;
}): Promise<Staff | null> {
  return getStaff(user.id);
}

export async function listStaff(): Promise<Staff[]> {
  const sql = await getSql();
  const rows = await sql<ProfileRow>`
    select user_id, email, username, name, role from staff_profiles order by created_at asc
  `;
  return rows.map(asStaff);
}

export async function findLoginEmail(identifier: string): Promise<string | null> {
  await ensureSentinelReady();
  const sql = await getSql();
  const raw = identifier.trim().toLowerCase();
  if (!raw) return null;
  if (raw.includes("@")) {
    const rows = await sql<{ email: string }>`select email from staff_profiles where lower(email) = ${raw}`;
    return rows[0]?.email ?? null;
  }
  const rows = await sql<{ email: string }>`select email from staff_profiles where username = ${raw}`;
  return rows[0]?.email ?? null;
}

export async function getHubSecret(): Promise<string> {
  await ensureSentinelReady();
  const sql = await getSql();
  const rows = await sql<{ value: string }>`select value from app_settings where key = 'hub_secret'`;
  return rows[0]?.value ?? "";
}

export function secretsMatch(given: string, expected: string): boolean {
  const a = Buffer.from(given);
  const b = Buffer.from(expected);
  if (a.length === 0 || a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

export function assertRole(staff: Staff, allowed: Role[]) {
  if (!allowed.includes(staff.role)) {
    const error = new Error("You do not have permission for that.");
    (error as Error & { status: number }).status = 403;
    throw error;
  }
}

const USERNAME_RE = /^[a-z][a-z0-9._-]{2,31}$/;

export function validateNewUser(input: {
  name: string;
  username: string;
  email: string;
  password: string;
  role: string;
}): { name: string; username: string; email: string; password: string; role: Role } {
  const name = input.name.trim().slice(0, 80);
  const username = normalizeUsername(input.username);
  const email = input.email.trim().toLowerCase();
  const password = input.password;
  const role = input.role;
  if (name.length < 2) throw new Error("Enter the person's name.");
  if (!USERNAME_RE.test(username)) {
    throw new Error("Usernames start with a letter and use 3–32 letters, numbers, dots or dashes.");
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error("Enter a valid email address.");
  if (password.length < 8 || !/[A-Za-z]/.test(password) || !/\d/.test(password)) {
    throw new Error("Passwords need at least 8 characters, including a letter and a number.");
  }
  if (role !== "admin" && role !== "operator" && role !== "viewer") {
    throw new Error("Choose a role.");
  }
  return { name, username, email, password, role };
}

export async function createStaffUser(input: {
  name: string;
  username: string;
  email: string;
  password: string;
  role: Role;
}): Promise<Staff> {
  const sql = await getSql();
  const taken = await sql<{ user_id: string }>`
    select user_id from staff_profiles where username = ${input.username} or lower(email) = ${input.email}
  `;
  if (taken[0]) throw new Error("That username or email is already in use.");
  const authUser = await sql<{ id: string }>`select id from "user" where lower(email) = ${input.email}`;
  if (authUser[0]) throw new Error("That email is already in use.");

  const userId = randomUUID();
  const now = new Date().toISOString();
  const hash = await hashPassword(input.password);
  await sql`
    insert into "user" ("id", "name", "email", "emailVerified", "createdAt", "updatedAt")
    values (${userId}, ${input.name}, ${input.email}, true, ${now}, ${now})
  `;
  await sql`
    insert into "account" ("id", "accountId", "providerId", "userId", "password", "createdAt", "updatedAt")
    values (${randomUUID()}, ${userId}, 'credential', ${userId}, ${hash}, ${now}, ${now})
  `;
  await sql`
    insert into staff_profiles (user_id, email, username, name, role)
    values (${userId}, ${input.email}, ${input.username}, ${input.name}, ${input.role})
  `;
  const staff = await getStaff(userId);
  if (!staff) throw new Error("The account could not be created.");
  return staff;
}

export async function removeStaffUser(userId: string, actorId: string): Promise<void> {
  if (userId === actorId) throw new Error("You cannot remove your own account.");
  const sql = await getSql();
  const target = await getStaff(userId);
  if (!target) throw new Error("That person is not on the team.");
  if (target.role === "admin") {
    const admins = await sql<{ n: number }>`select count(*) as n from staff_profiles where role = 'admin'`;
    if (Number(admins[0]?.n ?? 0) <= 1) throw new Error("Keep at least one administrator.");
  }
  await sql`delete from "session" where "userId" = ${userId}`;
  await sql`delete from "account" where "userId" = ${userId}`;
  await sql`delete from staff_profiles where user_id = ${userId}`;
  await sql`delete from "user" where id = ${userId}`;
}

export async function setStaffRole(userId: string, role: Role, actorId: string): Promise<void> {
  if (role !== "admin" && role !== "operator" && role !== "viewer") throw new Error("Choose a role.");
  const sql = await getSql();
  const target = await getStaff(userId);
  if (!target) throw new Error("That person is not on the team.");
  if (target.role === "admin" && role !== "admin") {
    const admins = await sql<{ n: number }>`select count(*) as n from staff_profiles where role = 'admin'`;
    if (Number(admins[0]?.n ?? 0) <= 1) throw new Error("Keep at least one administrator.");
    if (userId === actorId) throw new Error("Ask another administrator to change your role.");
  }
  await sql`update staff_profiles set role = ${role} where user_id = ${userId}`;
}

export async function changeOwnPassword(userId: string, current: string, next: string): Promise<void> {
  if (next.length < 8 || !/[A-Za-z]/.test(next) || !/\d/.test(next)) {
    throw new Error("Passwords need at least 8 characters, including a letter and a number.");
  }
  const sql = await getSql();
  const rows = await sql<{ password: string | null }>`
    select password from "account" where "userId" = ${userId} and "providerId" = 'credential'
  `;
  const hash = rows[0]?.password;
  if (!hash) throw new Error("This account does not use a password.");
  const ok = await verifyPassword({ hash, password: current });
  if (!ok) throw new Error("The current password is not correct.");
  const nextHash = await hashPassword(next);
  const now = new Date().toISOString();
  await sql`
    update "account" set password = ${nextHash}, "updatedAt" = ${now}
    where "userId" = ${userId} and "providerId" = 'credential'
  `;
}
