import { Router, Response } from "express";
import db from "../db";
import { requireAuth, AuthRequest } from "../middleware/auth";
import { SecurityScoreRecord } from "../types";

const router = Router();
router.use(requireAuth);

router.get("/", (req: AuthRequest, res: Response) => {
  let score = db
    .prepare("SELECT * FROM security_scores WHERE user_id = ?")
    .get(req.user!.userId) as SecurityScoreRecord | undefined;

  if (!score) {
    db.prepare(
      `INSERT INTO security_scores (user_id, score, critical, high, medium, low, total_scans) VALUES (?, 100, 0, 0, 0, 0, 0)`
    ).run(req.user!.userId);
    score = db.prepare("SELECT * FROM security_scores WHERE user_id = ?").get(req.user!.userId) as SecurityScoreRecord;
  }

  return res.json({ securityScore: score });
});

router.put("/", (req: AuthRequest, res: Response) => {
  const { score, critical, high, medium, low } = req.body || {};
  db.prepare(
    `UPDATE security_scores SET score = COALESCE(?, score), critical = COALESCE(?, critical), high = COALESCE(?, high), medium = COALESCE(?, medium), low = COALESCE(?, low), updated_at = datetime('now') WHERE user_id = ?`
  ).run(score, critical, high, medium, low, req.user!.userId);

  const updated = db.prepare("SELECT * FROM security_scores WHERE user_id = ?").get(req.user!.userId);
  return res.json({ securityScore: updated });
});

export default router;
