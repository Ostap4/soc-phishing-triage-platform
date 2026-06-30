import { useNavigate } from "react-router-dom";
import { useState, FormEvent } from "react";
import { Turnstile } from "@marsidev/react-turnstile";

type AuthMode = "login" | "register" | "forgot";

const API_URL = "";
const TURNSTILE_SITE_KEY = import.meta.env.VITE_TURNSTILE_SITE_KEY;

export default function AuthPage() {
  const navigate = useNavigate();

  const [mode, setMode] = useState<AuthMode>("login");

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const [captchaToken, setCaptchaToken] = useState<string | null>(null);
  const [captchaRequired, setCaptchaRequired] = useState(false);
  const [captchaKey, setCaptchaKey] = useState(0);

  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const [loading, setLoading] = useState(false);
  const [lockedSeconds, setLockedSeconds] = useState<number | null>(null);

  const resetCaptcha = () => {
    setCaptchaToken(null);
    setCaptchaKey((prev) => prev + 1);
  };

  const changeMode = (newMode: AuthMode) => {
    setMode(newMode);
    setError(null);
    setSuccess(null);
    setLockedSeconds(null);
    setCaptchaRequired(false);
    resetCaptcha();
  };

  const shouldShowCaptcha =
    mode === "register" || mode === "forgot" || captchaRequired;

  const validateForm = () => {
    if (!email) {
      setError("Email is required.");
      return false;
    }

    if (mode !== "forgot" && !password) {
      setError("Password is required.");
      return false;
    }

    if (shouldShowCaptcha && !captchaToken) {
      setError("Please complete CAPTCHA verification.");
      return false;
    }

    return true;
  };

  const handleAuth = async (e: FormEvent) => {
    e.preventDefault();

    setError(null);
    setSuccess(null);
    setLockedSeconds(null);

    if (!validateForm()) return;

    setLoading(true);

    try {
      if (mode === "forgot") {
        const response = await fetch(`${API_URL}/auth/forgot-password`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            email,
            captchaToken,
          }),
        });

        const data = await response.json();

        if (!response.ok) {
          throw new Error(data.error || data.detail || data.message || "Password reset request failed");
        }

        setSuccess("If the email is registered, a reset link has been sent.");
        resetCaptcha();
        return;
      }

      const response = await fetch(`${API_URL}/auth/${mode}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          email,
          password,
          captchaToken: shouldShowCaptcha ? captchaToken : null,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        if (data.captcha_required) {
          setCaptchaRequired(true);
        }

        if (data.retry_after_seconds) {
          setLockedSeconds(data.retry_after_seconds);
        }

        resetCaptcha();

        throw new Error(data.error || data.detail || data.message || "Authentication failed");
      }

      if (mode === "register") {
        setSuccess("Account created successfully. You can now sign in.");
        setMode("login");
        setPassword("");
        setCaptchaRequired(false);
        resetCaptcha();
        return;
      }

      localStorage.setItem("soc_user", data.email || email);

      if (data.access_token) {
        localStorage.setItem("soc_token", data.access_token);
      }

      if (data.user_id) {
        localStorage.setItem("soc_user_id", String(data.user_id));
      }

      navigate("/dashboard");
    } catch (err) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError("An unknown error occurred");
      }
    } finally {
      setLoading(false);
    }
  };

  const formatLockTime = (seconds: number) => {
    const minutes = Math.ceil(seconds / 60);
    return `${minutes} minute${minutes === 1 ? "" : "s"}`;
  };

  return (
    <div className="relative flex min-h-screen items-center justify-center px-4 cyber-grid">
      <div className="w-full max-w-md">
        <div className="mb-6 flex items-center justify-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-md neon-border bg-background/60">
            <span className="text-neon font-bold text-lg">⌬</span>
          </div>

          <div>
            <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">
              SOC Console
            </p>
            <h1 className="text-lg font-semibold text-foreground">
              Phishing Triage
            </h1>
          </div>
        </div>

        <div className="rounded-2xl border border-border bg-card/80 p-8 backdrop-blur-xl shadow-2xl">
          {mode !== "forgot" && (
            <div className="mb-6 flex rounded-lg border border-border bg-secondary p-1">
              <button
                type="button"
                onClick={() => changeMode("login")}
                className={`flex-1 rounded-md px-3 py-2 text-sm font-medium transition-all ${
                  mode === "login"
                    ? "bg-primary text-primary-foreground shadow-[var(--neon-glow)]"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                Login
              </button>

              <button
                type="button"
                onClick={() => changeMode("register")}
                className={`flex-1 rounded-md px-3 py-2 text-sm font-medium transition-all ${
                  mode === "register"
                    ? "bg-primary text-primary-foreground shadow-[var(--neon-glow)]"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                Register
              </button>
            </div>
          )}

          {mode === "forgot" && (
            <div className="mb-6">
              <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">
                Account recovery
              </p>
              <h2 className="mt-1 text-xl font-semibold text-foreground">
                Reset your password
              </h2>
              <p className="mt-2 text-sm text-muted-foreground">
                Enter your account email. If it exists, a secure reset link will be sent.
              </p>
            </div>
          )}

          <form onSubmit={handleAuth} className="space-y-4">
            <div>
              <label
                className="text-xs uppercase tracking-widest text-muted-foreground"
                htmlFor="email"
              >
                Email
              </label>

              <input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@company.com"
                className="mt-1.5 w-full rounded-md border border-input bg-background/60 px-3 py-2.5 text-sm text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary focus:ring-2 focus:ring-ring/40"
              />
            </div>

            {mode !== "forgot" && (
              <div>
                <label
                  className="text-xs uppercase tracking-widest text-muted-foreground"
                  htmlFor="password"
                >
                  Password
                </label>

                <input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="mt-1.5 w-full rounded-md border border-input bg-background/60 px-3 py-2.5 text-sm text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary focus:ring-2 focus:ring-ring/40"
                />
              </div>
            )}

            {shouldShowCaptcha && (
              <div className="rounded-md border border-border bg-background/40 p-3">
                <div className="mb-2 flex items-center justify-between">
                  <p className="text-xs uppercase tracking-widest text-muted-foreground">
                    Human verification
                  </p>

                  {mode === "login" && captchaRequired && (
                    <span className="text-[10px] uppercase tracking-widest text-warning">
                      Required after failed attempts
                    </span>
                  )}
                </div>

                <Turnstile
                  key={captchaKey}
                  siteKey={TURNSTILE_SITE_KEY}
                  onSuccess={(token) => {
                    setCaptchaToken(token);
                    setError(null);
                  }}
                  onError={() => {
                    setCaptchaToken(null);
                    setError("CAPTCHA failed. Please try again.");
                  }}
                  onExpire={() => {
                    setCaptchaToken(null);
                    setError("CAPTCHA expired. Please verify again.");
                  }}
                />
              </div>
            )}

            {lockedSeconds !== null && lockedSeconds > 0 && (
              <p className="rounded-md border border-warning/40 bg-warning/10 px-3 py-2 text-xs text-warning">
                Too many failed login attempts. Try again in approximately{" "}
                {formatLockTime(lockedSeconds)}.
              </p>
            )}

            {error && (
              <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
                {error}
              </p>
            )}

            {success && (
              <p className="rounded-md border border-success/40 bg-success/10 px-3 py-2 text-xs text-success">
                {success}
              </p>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full rounded-md bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground transition-all hover:brightness-110 disabled:opacity-60"
              style={{ boxShadow: "var(--neon-glow)" }}
            >
              {loading
                ? "Processing…"
                : mode === "login"
                  ? "Sign in"
                  : mode === "register"
                    ? "Create account"
                    : "Send reset link"}
            </button>
          </form>

          {mode === "login" && (
            <div className="mt-4 text-center">
              <button
                type="button"
                onClick={() => changeMode("forgot")}
                className="text-xs text-muted-foreground transition-colors hover:text-primary"
              >
                Forgot your password?
              </button>
            </div>
          )}

          {mode === "forgot" && (
            <div className="mt-4 text-center">
              <button
                type="button"
                onClick={() => changeMode("login")}
                className="text-xs text-muted-foreground transition-colors hover:text-primary"
              >
                Back to login
              </button>
            </div>
          )}

          <p className="mt-6 text-center text-xs text-muted-foreground">
            Secured channel · TLS 1.3 · Session keys rotated hourly
          </p>
        </div>
      </div>
    </div>
  );
}