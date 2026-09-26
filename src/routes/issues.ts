import { Router, Response } from "express";
import db from "../db";
import { requireAuth, AuthRequest } from "../middleware/auth";
import { IssueRecord, Severity } from "../types";

const router = Router();
router.use(requireAuth);

// GET /api/issues - list all issues for the user, optional filters
router.get("/", (req: AuthRequest, res: Response) => {
  const { severity, status, scanId } = req.query;
  let query = "SELECT * FROM issues WHERE user_id = ?";
  const params: any[] = [req.user!.userId];

  if (severity && severity !== "All") {
    query += " AND severity = ?";
    params.push(severity);
  }
  if (status) {
    query += " AND status = ?";
    params.push(status);
  }
  if (scanId) {
    query += " AND scan_id = ?";
    params.push(scanId);
  }
  query += " ORDER BY CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END, created_at DESC";

  const issues = db.prepare(query).all(...params) as IssueRecord[];
  return res.json({ issues });
});

// GET /api/issues/:id
router.get("/:id", (req: AuthRequest, res: Response) => {
  const issue = db
    .prepare("SELECT * FROM issues WHERE id = ? AND user_id = ?")
    .get(req.params.id, req.user!.userId) as IssueRecord | undefined;
  if (!issue) return res.status(404).json({ error: "Issue not found" });
  return res.json({ issue });
});

// PUT /api/issues/:id - update status (e.g. mark Fixed / Ignored) or apply the auto-fix
router.put("/:id", (req: AuthRequest, res: Response) => {
  const issue = db
    .prepare("SELECT * FROM issues WHERE id = ? AND user_id = ?")
    .get(req.params.id, req.user!.userId) as IssueRecord | undefined;
  if (!issue) return res.status(404).json({ error: "Issue not found" });

  const { status, fixedCode, fixExplanation } = req.body || {};
  const newStatus = status && ["Open", "Fixed", "Ignored"].includes(status) ? status : issue.status;
  const newFixedCode = fixedCode !== undefined ? fixedCode : issue.fixed_code;
  const newFixExplanation = fixExplanation !== undefined ? fixExplanation : issue.fix_explanation;

  db.prepare(
    `UPDATE issues SET status = ?, fixed_code = ?, fix_explanation = ? WHERE id = ? AND user_id = ?`
  ).run(newStatus, newFixedCode, newFixExplanation, req.params.id, req.user!.userId);

  // Recompute security score whenever an issue's status changes
  if (status) {
    recomputeUserScore(req.user!.userId);
  }

  const updated = db.prepare("SELECT * FROM issues WHERE id = ?").get(req.params.id);
  return res.json({ issue: updated });
});

function recomputeUserScore(userId: string) {
  const counts = db
    .prepare(
      `SELECT severity, COUNT(*) as cnt FROM issues WHERE user_id = ? AND status = 'Open' GROUP BY severity`
    )
    .all(userId) as { severity: Severity; cnt: number }[];

  const tally: Record<Severity, number> = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  counts.forEach((c) => (tally[c.severity] = c.cnt));

  let score = 100 - tally.Critical * 15 - tally.High * 8 - tally.Medium * 4 - tally.Low * 1;
  score = Math.max(0, Math.min(100, score));

  db.prepare(
    `UPDATE security_scores SET score = ?, critical = ?, high = ?, medium = ?, low = ?, updated_at = datetime('now') WHERE user_id = ?`
  ).run(score, tally.Critical, tally.High, tally.Medium, tally.Low, userId);
}

export default router;
export { recomputeUserScore };
