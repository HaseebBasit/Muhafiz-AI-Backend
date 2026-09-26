import { Router, Response } from "express";
import { v4 as uuidv4 } from "uuid";
import db from "../db";
import { requireAuth, AuthRequest } from "../middleware/auth";
import { ScanRecord } from "../types";

const router = Router();
router.use(requireAuth);

// GET /api/scans - list all scans for the logged-in user
router.get("/", (req: AuthRequest, res: Response) => {
  const scans = db
    .prepare("SELECT * FROM scans WHERE user_id = ? ORDER BY created_at DESC")
    .all(req.user!.userId) as ScanRecord[];
  return res.json({ scans });
});

// GET /api/scans/:id - one scan + its issues
router.get("/:id", (req: AuthRequest, res: Response) => {
  const scan = db
    .prepare("SELECT * FROM scans WHERE id = ? AND user_id = ?")
    .get(req.params.id, req.user!.userId) as ScanRecord | undefined;
  if (!scan) return res.status(404).json({ error: "Scan not found" });

  const issues = db
    .prepare("SELECT * FROM issues WHERE scan_id = ? AND user_id = ? ORDER BY severity")
    .all(scan.id, req.user!.userId);

  return res.json({ scan, issues });
});

// POST /api/scans - create a scan record manually (metadata only)
router.post("/", (req: AuthRequest, res: Response) => {
  const { name, language, codeSnippet } = req.body || {};
  if (!name || !language) {
    return res.status(400).json({ error: "name and language are required" });
  }
  const id = uuidv4();
  db.prepare(
    `INSERT INTO scans (id, user_id, name, language, code_snippet, status) VALUES (?, ?, ?, ?, ?, 'Queued')`
  ).run(id, req.user!.userId, name, language, codeSnippet || "");

  const scan = db.prepare("SELECT * FROM scans WHERE id = ?").get(id) as ScanRecord;
  return res.status(201).json({ scan });
});

export default router;
