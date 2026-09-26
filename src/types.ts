export type UserRole = "Developer" | "Security Engineer" | "Admin";

export interface UserRecord {
  id: string;
  full_name: string;
  email: string;
  password_hash: string;
  role: UserRole;
  created_at: string;
}

export interface PublicUser {
  id: string;
  fullName: string;
  email: string;
  role: UserRole;
  createdAt: string;
}

export interface AuthTokenPayload {
  userId: string;
  email: string;
  role: UserRole;
}

export type Severity = "Critical" | "High" | "Medium" | "Low";
export type IssueStatus = "Open" | "Fixed" | "Ignored";
export type ScanStatus = "Queued" | "Running" | "Completed" | "Failed";

export interface ScanRecord {
  id: string;
  user_id: string;
  name: string;
  language: string;
  code_snippet: string;
  status: ScanStatus;
  issues_found: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  created_at: string;
}

export interface IssueRecord {
  id: string;
  scan_id: string;
  user_id: string;
  title: string;
  description: string;
  severity: Severity;
  category: string;
  line_number: number;
  status: IssueStatus;
  original_code: string;
  fixed_code: string | null;
  fix_explanation: string | null;
  created_at: string;
}

export interface ProjectRecord {
  id: string;
  user_id: string;
  name: string;
  description: string;
  language: string;
  issues_count: number;
  security_score: number;
  last_scanned: string | null;
  created_at: string;
}

export interface SecurityScoreRecord {
  user_id: string;
  score: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  total_scans: number;
  updated_at: string;
}
