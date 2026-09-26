import { Router, Response } from "express";
import { v4 as uuidv4 } from "uuid";
import db from "../db";
import { requireAuth, AuthRequest } from "../middleware/auth";
import { analyzeCode, computeSecurityScore } from "../utils/scanner";
import { Severity } from "../types";

const router = Router();
router.use(requireAuth);

// POST /api/scan/code - run a "scan" over a code snippet (mock AI analysis engine)
router.post("/code", (req: AuthRequest, res: Response) => {
  const { code, language, fileName, projectId } = req.body || {};
  if (!code || !language) {
    return res.status(400).json({ error: "code and language are required" });
  }

  const userId = req.user!.userId;
  const detected = analyzeCode(code, language);

  const tally: Record<Severity, number> = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  detected.forEach((d) => (tally[d.severity] += 1));

  const scanId = uuidv4();
  db.prepare(
    `INSERT INTO scans (id, user_id, name, language, code_snippet, status, issues_found, critical_count, high_count, medium_count, low_count)
     VALUES (?, ?, ?, ?, ?, 'Completed', ?, ?, ?, ?, ?)`
  ).run(
    scanId,
    userId,
    fileName || `Scan ${new Date().toISOString().slice(0, 19)}`,
    language,
    code,
    detected.length,
    tally.Critical,
    tally.High,
    tally.Medium,
    tally.Low
  );

  const insertIssue = db.prepare(
    `INSERT INTO issues (id, scan_id, user_id, title, description, severity, category, line_number, status, original_code, fixed_code, fix_explanation)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Open', ?, ?, ?)`
  );

  const createdIssues = detected.map((d) => {
    const issueId = uuidv4();
    insertIssue.run(
      issueId,
      scanId,
      userId,
      d.title,
      d.description,
      d.severity,
      d.category,
      d.lineNumber,
      d.originalCode,
      d.fixedCode,
      d.fixExplanation
    );
    return { id: issueId, scanId, ...d };
  });

  // Recompute overall security score across ALL open issues for this user
  const counts = db
    .prepare(
      `SELECT severity, COUNT(*) as cnt FROM issues WHERE user_id = ? AND status = 'Open' GROUP BY severity`
    )
    .all(userId) as { severity: Severity; cnt: number }[];
  const overallTally: Record<Severity, number> = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  counts.forEach((c) => (overallTally[c.severity] = c.cnt));

  const score = computeSecurityScore(
    overallTally.Critical,
    overallTally.High,
    overallTally.Medium,
    overallTally.Low
  );

  db.prepare(
    `UPDATE security_scores SET score = ?, critical = ?, high = ?, medium = ?, low = ?, total_scans = total_scans + 1, updated_at = datetime('now') WHERE user_id = ?`
  ).run(score, overallTally.Critical, overallTally.High, overallTally.Medium, overallTally.Low, userId);

  if (projectId) {
    db.prepare(
      `UPDATE projects SET issues_count = ?, security_score = ?, last_scanned = datetime('now') WHERE id = ? AND user_id = ?`
    ).run(detected.length, computeSecurityScore(tally.Critical, tally.High, tally.Medium, tally.Low), projectId, userId);
  }

  const scan = db.prepare("SELECT * FROM scans WHERE id = ?").get(scanId);
  const securityScore = db.prepare("SELECT * FROM security_scores WHERE user_id = ?").get(userId);

  return res.status(201).json({ scan, issues: createdIssues, securityScore });
});

export default router;
