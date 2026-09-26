import "dotenv/config";
import express from "express";
import cors from "cors";
import authRoutes from "./routes/auth";
import scansRoutes from "./routes/scans";
import issuesRoutes from "./routes/issues";
import projectsRoutes from "./routes/projects";
import securityScoreRoutes from "./routes/securityScore";
import scanCodeRoutes from "./routes/scanCode";
import integrationsRoutes from "./routes/integrations";

const app = express();
const PORT = process.env.PORT || 5000;
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || "http://localhost:5173";

app.use(cors({ origin: CLIENT_ORIGIN, credentials: true }));
app.use(express.json({ limit: "2mb" }));

app.get("/api/health", (_req, res) => {
  res.json({ status: "ok", service: "MUHAFIZ AI Backend", time: new Date().toISOString() });
});

app.use("/api/auth", authRoutes);
app.use("/api/scans", scansRoutes);
app.use("/api/issues", issuesRoutes);
app.use("/api/projects", projectsRoutes);
app.use("/api/security-score", securityScoreRoutes);
app.use("/api/scan", scanCodeRoutes);
app.use("/api/integrations", integrationsRoutes);

app.use((_req, res) => {
  res.status(404).json({ error: "Route not found" });
});

// Centralized error handler
app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error(err);
  res.status(err.status || 500).json({ error: err.message || "Internal server error" });
});

app.listen(PORT, () => {
  console.log(`🛡️  MUHAFIZ AI backend running on http://localhost:${PORT}`);
});
