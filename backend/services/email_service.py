import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def send_reset_email(to_email, reset_link):
    """
    Ізольований сервіс для відправки транзакційних листів через SMTP.
    """
    smtp_server = os.getenv("SMTP_SERVER") or os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", 587))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")

    if not smtp_server or not smtp_user or not smtp_password:
        print("[ERROR] SMTP configuration is missing.")
        return False

    msg = MIMEMultipart()
    msg["From"] = f"SOC Phishing Triage System <{smtp_user}>"
    msg["To"] = to_email
    msg["Subject"] = "[SECURITY ALERT] Password Reset Request"

    html_content = f"""
    <html>
      <body style="background-color: #0d0e12; color: #ffffff; font-family: sans-serif; padding: 20px;">
        <div style="max-width: 500px; margin: 0 auto; border: 1px solid #27272a; background-color: #14151b; padding: 30px; border-radius: 8px;">
          <h2 style="color: #60a5fa; border-bottom: 1px solid #27272a; padding-bottom: 10px;">⌬ Password Reset</h2>
          <p>A password reset request was initiated for your SOC Analyst account.</p>
          <p style="color: #a1a1aa; font-size: 14px;">If you did not make this request, please inform your Blue Team Administrator immediately.</p>
          <div style="margin: 30px 0; text-align: center;">
            <a href="{reset_link}" style="background-color: #3b82f6; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">Reset Password</a>
          </div>
          <p style="color: #71717a; font-size: 12px; border-top: 1px solid #27272a; padding-top: 15px;">
            This secure link will expire in 15 minutes.<br>
            Secured Channel · TLS 1.3 Encryption
          </p>
        </div>
      </body>
    </html>
    """
    msg.attach(MIMEText(html_content, "html"))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_user, smtp_password)
        server.sendmail(smtp_user, to_email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"[ERROR] Email Service: {e}")
        return False
