import { Router, Response } from "express";
import { v4 as uuidv4 } from "uuid";
import db from "../db";
import { requireAuth, AuthRequest } from "../middleware/auth";
import { ProjectRecord } from "../types";

const router = Router();
router.use(requireAuth);

router.get("/", (req: AuthRequest, res: Response) => {
  const projects = db
    .prepare("SELECT * FROM projects WHERE user_id = ? ORDER BY created_at DESC")
    .all(req.user!.userId) as ProjectRecord[];
  return res.json({ projects });
});

router.post("/", (req: AuthRequest, res: Response) => {
  const { name, description, language } = req.body || {};
  if (!name) return res.status(400).json({ error: "name is required" });

  const id = uuidv4();
  db.prepare(
    `INSERT INTO projects (id, user_id, name, description, language, issues_count, security_score) VALUES (?, ?, ?, ?, ?, 0, 100)`
  ).run(id, req.user!.userId, name, description || "", language || "JavaScript");

  const project = db.prepare("SELECT * FROM projects WHERE id = ?").get(id);
  return res.status(201).json({ project });
});

router.put("/:id", (req: AuthRequest, res: Response) => {
  const project = db
    .prepare("SELECT * FROM projects WHERE id = ? AND user_id = ?")
    .get(req.params.id, req.user!.userId) as ProjectRecord | undefined;
  if (!project) return res.status(404).json({ error: "Project not found" });

  const {
    name = project.name,
    description = project.description,
    language = project.language,
    issuesCount = project.issues_count,
    securityScore = project.security_score,
    lastScanned = project.last_scanned,
  } = req.body || {};

  db.prepare(
    `UPDATE projects SET name = ?, description = ?, language = ?, issues_count = ?, security_score = ?, last_scanned = ? WHERE id = ? AND user_id = ?`
  ).run(name, description, language, issuesCount, securityScore, lastScanned, req.params.id, req.user!.userId);

  const updated = db.prepare("SELECT * FROM projects WHERE id = ?").get(req.params.id);
  return res.json({ project: updated });
});

router.delete("/:id", (req: AuthRequest, res: Response) => {
  const result = db
    .prepare("DELETE FROM projects WHERE id = ? AND user_id = ?")
    .run(req.params.id, req.user!.userId);
  if (result.changes === 0) return res.status(404).json({ error: "Project not found" });
  return res.json({ success: true });
});

export default router;
