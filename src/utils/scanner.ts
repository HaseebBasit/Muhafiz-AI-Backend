import { Severity } from "../types";

export interface DetectedIssue {
  title: string;
  description: string;
  severity: Severity;
  category: string;
  lineNumber: number;
  originalCode: string;
  fixedCode: string;
  fixExplanation: string;
}

interface Rule {
  pattern: RegExp;
  title: string;
  description: string;
  severity: Severity;
  category: string;
  buildFix: (line: string) => { fixedCode: string; explanation: string };
}

const RULES: Rule[] = [
  {
    pattern: /eval\s*\(/,
    title: "Use of eval() — Arbitrary Code Execution",
    description:
      "eval() executes arbitrary strings as code, allowing attackers to inject and run malicious scripts if user input reaches it.",
    severity: "Critical",
    category: "Code Injection",
    buildFix: (line) => ({
      fixedCode: line.replace(/eval\s*\((.*)\)/, "JSON.parse($1)"),
      explanation:
        "Replaced eval() with a safe alternative like JSON.parse() or a dedicated parser. Never execute dynamic strings as code.",
    }),
  },
  {
    pattern: /(SELECT|INSERT|UPDATE|DELETE).*(\+|\$\{)/i,
    title: "SQL Injection via String Concatenation",
    description:
      "Building SQL queries via string concatenation or template literals with unsanitized input allows attackers to manipulate queries.",
    severity: "Critical",
    category: "SQL Injection",
    buildFix: (line) => ({
      fixedCode: line + "  // Use parameterized queries: db.query('... WHERE id = ?', [id])",
      explanation:
        "Use parameterized queries or prepared statements instead of concatenating user input directly into SQL strings.",
    }),
  },
  {
    pattern: /innerHTML\s*=/,
    title: "Cross-Site Scripting (XSS) via innerHTML",
    description:
      "Assigning untrusted data to innerHTML can allow attackers to inject scripts that execute in the victim's browser.",
    severity: "High",
    category: "XSS",
    buildFix: (line) => ({
      fixedCode: line.replace("innerHTML", "textContent"),
      explanation:
        "Use textContent for plain text, or sanitize HTML with a library like DOMPurify before rendering.",
    }),
  },
  {
    pattern: /(api[_-]?key|secret|password|token)\s*[:=]\s*["'`][A-Za-z0-9_\-]{6,}["'`]/i,
    title: "Hardcoded Secret / Credential",
    description:
      "Secrets, API keys, or passwords hardcoded in source code can be leaked via version control or bundled client code.",
    severity: "Critical",
    category: "Secrets Exposure",
    buildFix: () => ({
      fixedCode: "const apiKey = process.env.API_KEY; // load from environment / secret manager",
      explanation:
        "Move secrets to environment variables or a secrets manager (e.g. Vault, AWS Secrets Manager) and never commit them to source control.",
    }),
  },
  {
    pattern: /exec\s*\(|child_process/,
    title: "OS Command Injection Risk",
    description:
      "Passing unsanitized input to shell execution functions can let an attacker run arbitrary system commands.",
    severity: "Critical",
    category: "Command Injection",
    buildFix: (line) => ({
      fixedCode: line + "  // Use execFile() with an argument array instead of a shell string",
      explanation:
        "Use execFile()/spawn() with an explicit argument array instead of building a shell command string, and validate/allowlist all inputs.",
    }),
  },
  {
    pattern: /md5|sha1(?!256)/i,
    title: "Weak Cryptographic Hash",
    description:
      "MD5 and SHA1 are cryptographically broken and unsuitable for password hashing or integrity-sensitive operations.",
    severity: "Medium",
    category: "Weak Cryptography",
    buildFix: (line) => ({
      fixedCode: line.replace(/md5|sha1/i, "sha256"),
      explanation:
        "Use bcrypt/argon2 for password hashing, or SHA-256/SHA-3 for integrity checks.",
    }),
  },
  {
    pattern: /http:\/\//,
    title: "Insecure HTTP Protocol",
    description:
      "Data sent over plain HTTP is unencrypted and can be intercepted or modified in transit (man-in-the-middle).",
    severity: "Medium",
    category: "Insecure Transport",
    buildFix: (line) => ({
      fixedCode: line.replace("http://", "https://"),
      explanation: "Always use HTTPS/TLS for network requests to protect data in transit.",
    }),
  },
  {
    pattern: /catch\s*\(\s*\w*\s*\)\s*{\s*}/,
    title: "Empty Catch Block Swallows Errors",
    description:
      "Silently swallowing exceptions can hide security-relevant failures (e.g. failed auth checks) from logs and monitoring.",
    severity: "Low",
    category: "Error Handling",
    buildFix: (line) => ({
      fixedCode: line.replace("{}", "{ logger.error(err); }"),
      explanation: "Log or handle the caught error instead of ignoring it silently.",
    }),
  },
  {
    pattern: /disable[-_]?ssl|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED/i,
    title: "TLS Certificate Verification Disabled",
    description:
      "Disabling TLS certificate validation exposes the application to man-in-the-middle attacks.",
    severity: "High",
    category: "Insecure Transport",
    buildFix: (line) => ({
      fixedCode: "// " + line + "  -- removed, keep certificate verification enabled",
      explanation: "Remove the flag that disables certificate verification; fix the underlying certificate issue instead.",
    }),
  },
  {
    pattern: /Math\.random\(\)/,
    title: "Insecure Randomness for Security Purpose",
    description:
      "Math.random() is not cryptographically secure and should not be used to generate tokens, IDs, or keys.",
    severity: "Medium",
    category: "Weak Cryptography",
    buildFix: (line) => ({
      fixedCode: line.replace("Math.random()", "crypto.randomBytes(16).toString('hex')"),
      explanation: "Use crypto.randomBytes() (Node) or Web Crypto's getRandomValues() for security-sensitive randomness.",
    }),
  },
];

export function analyzeCode(code: string, language: string): DetectedIssue[] {
  const lines = code.split("\n");
  const found: DetectedIssue[] = [];

  lines.forEach((line, idx) => {
    for (const rule of RULES) {
      if (rule.pattern.test(line)) {
        const fix = rule.buildFix(line);
        found.push({
          title: rule.title,
          description: rule.description,
          severity: rule.severity,
          category: rule.category,
          lineNumber: idx + 1,
          originalCode: line.trim(),
          fixedCode: fix.fixedCode.trim(),
          fixExplanation: fix.explanation,
        });
      }
    }
  });

  // Guarantee at least a baseline informational finding so scans never look "empty"
  if (found.length === 0) {
    found.push({
      title: "No Critical Patterns Detected",
      description:
        `Static analysis for ${language} did not match any known high-risk patterns in this snippet. Consider deeper manual review and dependency auditing.`,
      severity: "Low",
      category: "General",
      lineNumber: 1,
      originalCode: lines[0]?.trim() || "",
      fixedCode: lines[0]?.trim() || "",
      fixExplanation: "No automatic fix required. Run a full dependency and configuration audit periodically.",
    });
  }

  return found;
}

export function computeSecurityScore(critical: number, high: number, medium: number, low: number): number {
  let score = 100;
  score -= critical * 15;
  score -= high * 8;
  score -= medium * 4;
  score -= low * 1;
  return Math.max(0, Math.min(100, score));
}
