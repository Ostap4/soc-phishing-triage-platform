import { useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Turnstile } from "@marsidev/react-turnstile";

const API_URL = "";
const TURNSTILE_SITE_KEY = import.meta.env.VITE_TURNSTILE_SITE_KEY;

export default function ResetPassword() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get("token");

  const navigate = useNavigate();

  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const [captchaToken, setCaptchaToken] = useState(null);
  const [captchaKey, setCaptchaKey] = useState(0);

  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);

  const [loading, setLoading] = useState(false);

  const resetCaptcha = () => {
  setCaptchaToken(null);
  setCaptchaKey((prev) => prev + 1);
};

const validatePasswordValue = (password) => {
  if (!password) {
    return "Password is required.";
  }

  if (password.length < 8) {
    return "Password must be at least 8 characters long.";
  }

  if (!/[a-z]/.test(password)) {
    return "Password must contain at least one lowercase letter.";
  }

  if (!/[A-Z]/.test(password)) {
    return "Password must contain at least one uppercase letter.";
  }

  if (!/\d/.test(password)) {
    return "Password must contain at least one number.";
  }

  return null;
};

const validateForm = () => {
  if (!password || !confirmPassword) {
    setError("Please fill in both password fields.");
    return false;
  }

  if (password !== confirmPassword) {
    setError("Passwords do not match.");
    return false;
  }

  const passwordError = validatePasswordValue(password);

  if (passwordError) {
    setError(passwordError);
    return false;
  }

  if (!captchaToken) {
    setError("Please complete CAPTCHA verification.");
    return false;
  }

  return true;
};

const handleReset = async (e) => {
  e.preventDefault();

  setError(null);
  setSuccess(null);

  if (!token) {
    setError("Invalid reset link. No token provided.");
    return;
  }

  if (!validateForm()) {
    return;
  }

  setLoading(true);

  try {
    const response = await fetch(`${API_URL}/auth/reset-password`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        token,
        password,
        captchaToken,
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      resetCaptcha();

      if (data.details && Array.isArray(data.details)) {
        throw new Error(data.details.join(" "));
      }

      throw new Error(
        data.error || data.detail || data.message || "Failed to reset password"
      );
    }

    setSuccess("Password successfully updated. Redirecting to login...");

    setPassword("");
    setConfirmPassword("");
    resetCaptcha();

    setTimeout(() => {
      navigate("/login");
    }, 1200);
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

  if (!token) {
    return (
      <div className="relative flex min-h-screen items-center justify-center px-4 cyber-grid">
        <div className="w-full max-w-md rounded-2xl border border-border bg-card/80 p-8 text-center backdrop-blur-xl shadow-2xl">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-md neon-border bg-background/60">
            <span className="text-neon text-xl font-bold">⌬</span>
          </div>

          <h2 className="text-xl font-bold text-foreground">Invalid reset link</h2>

          <p className="mt-3 text-sm text-muted-foreground">
            No reset token was provided. Please request a new password reset link.
          </p>

          <button
            type="button"
            onClick={() => navigate("/login")}
            className="mt-6 w-full rounded-md bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground transition-all hover:brightness-110"
            style={{ boxShadow: "var(--neon-glow)" }}
          >
            Back to login
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="relative flex min-h-screen items-center justify-center px-4 cyber-grid">
      <div className="w-full max-w-md">
        <div className="mb-6 flex items-center justify-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-md neon-border bg-background/60">
            <span className="text-neon text-lg font-bold">⌬</span>
          </div>

          <div>
            <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">
              SOC Console
            </p>
            <h1 className="text-lg font-semibold text-foreground">
              Password Recovery
            </h1>
          </div>
        </div>

        <div className="rounded-2xl border border-border bg-card/80 p-8 backdrop-blur-xl shadow-2xl">
          <div className="mb-6">
            <p className="text-xs uppercase tracking-[0.3em] text-muted-foreground">
              Secure reset
            </p>

            <h2 className="mt-1 text-xl font-bold text-foreground">
              Set new password
            </h2>

            <p className="mt-2 text-sm text-muted-foreground">
              Create a new password for your SOC Analyst account. The reset link is time-limited.
            </p>
          </div>

          <form onSubmit={handleReset} className="space-y-4">
            <div>
              <label
                className="text-xs uppercase tracking-widest text-muted-foreground"
                htmlFor="password"
              >
                New password
              </label>

              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="mt-1.5 w-full rounded-md border border-input bg-background/60 px-3 py-2.5 text-sm text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary focus:ring-2 focus:ring-ring/40"
                required
              />
            </div>

            <div>
              <label
                className="text-xs uppercase tracking-widest text-muted-foreground"
                htmlFor="confirmPassword"
              >
                Confirm password
              </label>

              <input
                id="confirmPassword"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="••••••••"
                className="mt-1.5 w-full rounded-md border border-input bg-background/60 px-3 py-2.5 text-sm text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary focus:ring-2 focus:ring-ring/40"
                required
              />
            </div>

            <div className="rounded-md border border-border bg-background/40 p-3">
              <div className="mb-2 flex items-center justify-between">
                <p className="text-xs uppercase tracking-widest text-muted-foreground">
                  Human verification
                </p>

                <span className="text-[10px] uppercase tracking-widest text-muted-foreground">
                  Required
                </span>
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
              {loading ? "Updating password..." : "Update password"}
            </button>
          </form>

          <div className="mt-4 text-center">
            <button
              type="button"
              onClick={() => navigate("/login")}
              className="text-xs text-muted-foreground transition-colors hover:text-primary"
            >
              Back to login
            </button>
          </div>

          <p className="mt-6 text-center text-xs text-muted-foreground">
            Secured channel · TLS 1.3 · Password reset token validation
          </p>
        </div>
      </div>
    </div>
  );
}