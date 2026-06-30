
import { useEffect, useState, useCallback, type DragEvent, type ChangeEvent } from "react";
import { useNavigate } from "react-router-dom";

const API_BASE_URL = import.meta.env.VITE_API_URL || "";


type Verdict = "Malicious" | "Suspicious" | "Safe";

interface AIReport {
  urgency_level?: number;
  financial_pressure?: boolean;
  manipulation_tactics?: string[];
  ai_verdict?: Verdict | string;
  brief_reason?: string;
  error?: string;
}

interface AnalysisResult {
  fileName: string;
  verdict: Verdict;
  maliciousUrls: number;
  maliciousFiles: number;
  urlsCount: number;
  attachmentsCount: number;
  reasoning: string;
  aiReport?: AIReport | null;
}

interface ScanHistoryItem {
  id: number;
  filename: string;
  status: string;
  created_at: string | null;
  malicious_urls: number;
  malicious_files: number;
  ai_verdict: string;
  brief_reason?: string | null;
  urgency_level?: number | null;
  financial_pressure?: boolean | null;
}

export default function Dashboard() {
  const navigate = useNavigate();
  const [userEmail, setUserEmail] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);


  const fetchHistory = useCallback(async () => {
  const token = localStorage.getItem("soc_token");

    if (!token) {
      return;
    }

    setHistoryLoading(true);

    try {
      const response = await fetch(`${API_BASE_URL}/api/scans/history`, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Failed to load scan history");
      }

      setHistory(data.history || []);
    } catch (err) {
      console.error("History load failed:", err);
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  useEffect(() => {
    const email = localStorage.getItem("soc_user");

    if (!email) {
      navigate("/login");
    } else {
      setUserEmail(email);
      void fetchHistory();
    }
  }, [navigate]);

  const handleUpload = useCallback(async (file: File) => {
    setIsAnalyzing(true);
    setResult(null);
    void fetchHistory();


    try {
      const token = localStorage.getItem("soc_token");

      if (!token) {
        throw new Error("Missing auth token. Please log in again.");
      }

      const formData = new FormData();
      formData.append("file", file);

      const response = await fetch(`${API_BASE_URL}/api/scans/upload`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
        },
        body: formData,
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || data.detail || "Scan failed");
      }

      let verdict: Verdict = "Safe";

      if (data.ai_verdict === "Malicious") {
        verdict = "Malicious";
      } else if (data.ai_verdict === "Suspicious") {
        verdict = "Suspicious";
      } else if (data.malicious_urls > 0 || data.malicious_files > 0) {
        verdict = "Suspicious";
      }

      setResult({
        fileName: data.filename || file.name,
        verdict,
        maliciousUrls: data.malicious_urls ?? 0,
        maliciousFiles: data.malicious_files ?? 0,
        urlsCount: data.urls_count ?? 0,
        attachmentsCount: data.attachments_count ?? 0,
        reasoning:
          data.ai_report?.brief_reason ||
          data.ai_verdict ||
          "Analysis completed. No detailed AI reasoning was returned by the backend.",
        aiReport: data.ai_report ?? null,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Unknown upload error";

      setResult({
        fileName: file.name,
        verdict: "Suspicious",
        maliciousUrls: 0,
        maliciousFiles: 0,
        urlsCount: 0,
        attachmentsCount: 0,
        reasoning: `Upload failed: ${message}`,
        aiReport: null,
      });
    } finally {
      setIsAnalyzing(false);
    }
  }, []);
  

  

  const onDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) void handleUpload(file);
  };

  const onFileInput = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) void handleUpload(file);
  };

  const handleLogout = () => {
    localStorage.removeItem("soc_user");
    localStorage.removeItem("soc_token");
    localStorage.removeItem("soc_user_id");
    navigate("/login");
  };

  if (!userEmail) return null;

  return (
    <div className="min-h-screen">
      <header className="border-b border-border bg-card/60 backdrop-blur-md">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-md neon-border bg-background/60">
              <span className="text-neon font-bold">⌬</span>
            </div>
            <div>
              <h1 className="text-sm font-semibold tracking-widest text-foreground uppercase">SOC // Phishing Triage</h1>
              <p className="text-xs text-muted-foreground">Threat Intelligence Console</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <div className="hidden sm:flex items-center gap-2 text-xs">
              <span className="h-2 w-2 rounded-full bg-success animate-pulse" />
              <span className="text-muted-foreground">Connected</span>
            </div>
            <div className="text-right">
              <p className="text-xs text-muted-foreground">Signed in</p>
              <p className="text-sm text-foreground font-medium">{userEmail}</p>
            </div>
            <button
              onClick={handleLogout}
              className="rounded-md border border-border bg-secondary px-3 py-1.5 text-xs font-medium text-foreground transition-colors hover:bg-accent"
            >
              Sign out
            </button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl px-6 py-10">
        <section className="mb-8">
          <h2 className="text-2xl font-semibold text-foreground">Submit an email for triage</h2>
          <p className="mt-1 text-sm text-muted-foreground">
            Drop a <code className="text-neon">.eml</code> file below. The model returns a verdict, indicator counts, and reasoning.
          </p>
        </section>

        <div
          onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={onDrop}
          className={`relative cyber-grid rounded-xl border-2 border-dashed p-12 text-center transition-all ${
            isDragging
              ? "border-neon bg-primary/10 scale-[1.01]"
              : "border-border bg-card/40 hover:border-primary/60"
          }`}
        >
          <div className="mx-auto flex max-w-md flex-col items-center gap-4">
            <div className="flex h-16 w-16 items-center justify-center rounded-full neon-border bg-background/80">
              <svg className="h-7 w-7 text-neon" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v12m0 0l-4-4m4 4l4-4M4 20h16" />
              </svg>
            </div>
            <div>
              <p className="text-lg font-semibold text-foreground">Drag & drop your .eml file</p>
              <p className="mt-1 text-sm text-muted-foreground">or click to browse from your device</p>
            </div>
            <label className="cursor-pointer rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground transition-all hover:brightness-110">
              Select file
              <input type="file" accept=".eml" className="hidden" onChange={onFileInput} />
            </label>
          </div>

          {isAnalyzing && (
            <div className="absolute inset-0 flex items-center justify-center rounded-xl bg-background/80 backdrop-blur-sm">
              <div className="flex flex-col items-center gap-3">
                <div className="h-10 w-10 animate-spin rounded-full border-2 border-border border-t-neon" />
                <p className="text-sm text-neon tracking-wider uppercase">Analyzing payload…</p>
              </div>
            </div>
          )}
        </div>

        {result && <ResultsPanel result={result} />}
        <ScanHistoryPanel history={history} loading={historyLoading} />
      </main>
    </div>
  );


  function ScanHistoryPanel({
    history,
    loading,
  }: {
  history: ScanHistoryItem[];
  loading: boolean;
}): import("react").JSX.Element {
  const formatDate = (value: string | null) => {
    if (!value) return "Unknown";

    return new Date(value).toLocaleString(undefined, {
      year: "numeric",
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  const verdictClass = (verdict: string) => {
    if (verdict === "Malicious") return "text-destructive";
    if (verdict === "Suspicious") return "text-warning";
    if (verdict === "Safe") return "text-success";
    return "text-muted-foreground";
  };

      return (
        <section className="mt-10 rounded-xl border border-border bg-card p-6">
          <div className="mb-5 flex items-center justify-between">
            <div>
              <h3 className="text-lg font-semibold text-foreground">
                Analysis history
              </h3>
              <p className="mt-1 text-sm text-muted-foreground">
                Recent email triage results linked to your analyst account.
              </p>
            </div>

            {loading && (
              <span className="text-xs uppercase tracking-widest text-neon">
                Loading...
              </span>
            )}
          </div>

          {history.length === 0 ? (
            <div className="rounded-lg border border-border bg-background/40 p-5 text-sm text-muted-foreground">
              No scans yet. Upload an .eml file to create your first analysis record.
            </div>
          ) : (
            <div className="overflow-hidden rounded-lg border border-border">
              <table className="w-full text-left text-sm">
                <thead className="border-b border-border bg-secondary/70 text-xs uppercase tracking-widest text-muted-foreground">
                  <tr>
                    <th className="px-4 py-3">File</th>
                    <th className="px-4 py-3">Date</th>
                    <th className="px-4 py-3">Verdict</th>
                    <th className="px-4 py-3">URLs</th>
                    <th className="px-4 py-3">Files</th>
                    <th className="px-4 py-3">Status</th>
                  </tr>
                </thead>

                <tbody>
                  {history.map((item) => (
                    <tr
                      key={item.id}
                      className="border-b border-border/60 bg-background/20 last:border-0 hover:bg-background/40"
                    >
                      <td className="max-w-[220px] truncate px-4 py-3 font-mono text-xs text-foreground">
                        {item.filename}
                      </td>

                      <td className="px-4 py-3 text-xs text-muted-foreground">
                        {formatDate(item.created_at)}
                      </td>

                      <td className={`px-4 py-3 font-semibold ${verdictClass(item.ai_verdict)}`}>
                        {item.ai_verdict || "Unknown"}
                      </td>

                      <td className="px-4 py-3 tabular-nums text-foreground">
                        {item.malicious_urls}
                      </td>

                      <td className="px-4 py-3 tabular-nums text-foreground">
                        {item.malicious_files}
                      </td>

                      <td className="px-4 py-3 text-xs text-muted-foreground">
                        {item.status}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      );
    }



function ResultsPanel({ result }: { result: AnalysisResult }) {
  const verdictStyles: Record<Verdict, { bg: string; text: string; ring: string; label: string }> = {
    Malicious: {
      bg: "bg-destructive/15",
      text: "text-destructive",
      ring: "ring-destructive/50 shadow-[0_0_30px_oklch(0.65_0.25_25/0.4)]",
      label: "Threat confirmed",
    },
    Suspicious: {
      bg: "bg-warning/15",
      text: "text-warning",
      ring: "ring-warning/50 shadow-[0_0_30px_oklch(0.82_0.17_85/0.3)]",
      label: "Manual review",
    },
    Safe: {
      bg: "bg-success/15",
      text: "text-success",
      ring: "ring-success/50 shadow-[0_0_30px_oklch(0.72_0.17_150/0.3)]",
      label: "No threats found",
    },
  };
  const s = verdictStyles[result.verdict];

  return (
    <section className="mt-10 space-y-4">
      <div className="flex items-baseline justify-between">
        <h3 className="text-lg font-semibold text-foreground">Triage report</h3>
        <p className="text-xs text-muted-foreground font-mono">{result.fileName}</p>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <div className={`rounded-xl border border-border ${s.bg} p-5 ring-1 ${s.ring}`}>
          <p className="text-xs uppercase tracking-widest text-muted-foreground">AI Verdict</p>
          <p className={`mt-3 text-3xl font-bold ${s.text}`}>{result.verdict}</p>
          <p className={`mt-1 text-xs ${s.text}/80`}>{s.label}</p>
        </div>

        <MetricCard
          label="Malicious URLs detected"
          value={result.maliciousUrls}
          accent={result.maliciousUrls > 0 ? "text-destructive" : "text-success"}
        />
        <MetricCard
          label="Malicious files detected"
          value={result.maliciousFiles}
          accent={result.maliciousFiles > 0 ? "text-destructive" : "text-success"}
        />
        <MetricCard
          label="Attachments found"
          value={result.attachmentsCount}
          accent={result.attachmentsCount > 0 ? "text-warning" : "text-success"}
        />
      </div>

      <div className="rounded-xl border border-border bg-card p-6">
        <div className="flex items-center gap-2">
          <span className="text-neon">◆</span>
          <p className="text-xs uppercase tracking-widest text-muted-foreground">AI Reasoning</p>
        </div>
        <p className="mt-3 text-sm leading-relaxed text-foreground/90">{result.reasoning}</p>
      </div>
    </section>
  );
}

  function MetricCard({ label, value, accent }: { label: string; value: number; accent: string }) {
    return (
      <div className="rounded-xl border border-border bg-card p-5">
        <p className="text-xs uppercase tracking-widest text-muted-foreground">{label}</p>
        <p className={`mt-3 text-4xl font-bold tabular-nums ${accent}`}>{value}</p>
      </div>
    );
  }
}





