import { Router, Response } from "express";
import db from "../db";
import { requireAuth, AuthRequest } from "../middleware/auth";

const router = Router();
router.use(requireAuth);

router.get("/", (req: AuthRequest, res: Response) => {
  const rows = db
    .prepare("SELECT integration_key, enabled FROM integrations WHERE user_id = ?")
    .all(req.user!.userId) as { integration_key: string; enabled: number }[];
  return res.json({
    integrations: rows.map((r) => ({ key: r.integration_key, enabled: !!r.enabled })),
  });
});

router.put("/:key", (req: AuthRequest, res: Response) => {
  const { enabled } = req.body || {};
  db.prepare(
    `INSERT INTO integrations (user_id, integration_key, enabled) VALUES (?, ?, ?)
     ON CONFLICT(user_id, integration_key) DO UPDATE SET enabled = excluded.enabled`
  ).run(req.user!.userId, req.params.key, enabled ? 1 : 0);
  return res.json({ key: req.params.key, enabled: !!enabled });
});

export default router;
