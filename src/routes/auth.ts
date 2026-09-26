import { Router, Request, Response } from "express";
import bcrypt from "bcryptjs";
import { v4 as uuidv4 } from "uuid";
import db from "../db";
import { signAccessToken, signRefreshToken, verifyRefreshToken } from "../utils/jwt";
import { requireAuth, AuthRequest } from "../middleware/auth";
import { UserRecord, UserRole, PublicUser } from "../types";

const router = Router();
const VALID_ROLES: UserRole[] = ["Developer", "Security Engineer", "Admin"];

function toPublicUser(u: UserRecord): PublicUser {
  return {
    id: u.id,
    fullName: u.full_name,
    email: u.email,
    role: u.role,
    createdAt: u.created_at,
  };
}

router.post("/signup", async (req: Request, res: Response) => {
  try {
    const { fullName, email, password, role } = req.body || {};

    if (!fullName || !email || !password) {
      return res.status(400).json({ error: "Full name, email, and password are required" });
    }
    if (String(password).length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters" });
    }
    const finalRole: UserRole = VALID_ROLES.includes(role) ? role : "Developer";
    const normalizedEmail = String(email).trim().toLowerCase();

    const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(normalizedEmail);
    if (existing) {
      return res.status(409).json({ error: "An account with this email already exists" });
    }

    const id = uuidv4();
    const passwordHash = await bcrypt.hash(password, 10);

    db.prepare(
      `INSERT INTO users (id, full_name, email, password_hash, role) VALUES (?, ?, ?, ?, ?)`
    ).run(id, fullName, normalizedEmail, passwordHash, finalRole);

    db.prepare(
      `INSERT INTO security_scores (user_id, score, critical, high, medium, low, total_scans) VALUES (?, 100, 0, 0, 0, 0, 0)`
    ).run(id);

    const seedIntegrations = ["github", "gitlab", "jira", "slack", "vscode", "ci-cd"];
    const insertIntegration = db.prepare(
      `INSERT OR IGNORE INTO integrations (user_id, integration_key, enabled) VALUES (?, ?, 0)`
    );
    seedIntegrations.forEach((key) => insertIntegration.run(id, key));

    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(id) as UserRecord;
    const payload = { userId: user.id, email: user.email, role: user.role };
    const accessToken = signAccessToken(payload);
    const refreshToken = signRefreshToken(payload);

    return res.status(201).json({ user: toPublicUser(user), accessToken, refreshToken });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Internal server error during signup" });
  }
});

router.post("/login", async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }
    const normalizedEmail = String(email).trim().toLowerCase();
    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(normalizedEmail) as
      | UserRecord
      | undefined;

    if (!user) {
      return res.status(401).json({ error: "Invalid email or password" });
    }
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const payload = { userId: user.id, email: user.email, role: user.role };
    const accessToken = signAccessToken(payload);
    const refreshToken = signRefreshToken(payload);

    return res.json({ user: toPublicUser(user), accessToken, refreshToken });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Internal server error during login" });
  }
});

router.post("/refresh", (req: Request, res: Response) => {
  try {
    const { refreshToken } = req.body || {};
    if (!refreshToken) return res.status(400).json({ error: "refreshToken is required" });

    const payload = verifyRefreshToken(refreshToken);
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(payload.userId) as
      | UserRecord
      | undefined;
    if (!user) return res.status(401).json({ error: "User no longer exists" });

    const newPayload = { userId: user.id, email: user.email, role: user.role };
    const accessToken = signAccessToken(newPayload);
    const newRefreshToken = signRefreshToken(newPayload);
    return res.json({ accessToken, refreshToken: newRefreshToken });
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired refresh token" });
  }
});

router.get("/me", requireAuth, (req: AuthRequest, res: Response) => {
  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user!.userId) as
    | UserRecord
    | undefined;
  if (!user) return res.status(404).json({ error: "User not found" });
  return res.json({ user: toPublicUser(user) });
});

export default router;
