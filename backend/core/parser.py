from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse
import re
import hashlib


class EMLParser:
    """
    Core module for parsing .eml files and extracting Indicators of Compromise (IOCs).
    """

    def __init__(self, file_path):
        self.file_path = file_path
        self.msg = self._load_email()
        self.extracted_data = {
            "headers": {},
            "body_plain": "",
            "body_html": "",
            "body": "",
            "urls": [],
            "mismatched_links": [],
            "attachments": [],
        }

    def _load_email(self):
        """Loads and parses the .eml file into an email object."""
        try:
            with open(self.file_path, "rb") as f:
                return BytesParser(policy=policy.default).parse(f)
        except Exception as e:
            print(f"Error loading file: {e}")
            return None

    def extract_headers(self):
        """Extracts basic routing headers (From, To, Subject, Date)."""
        if not self.msg:
            return

        target_headers = ["From", "To", "Subject", "Date"]
        for header in target_headers:
            self.extracted_data["headers"][header] = self.msg.get(header, "Not Found")

    def extract_body(self):
        """Extracts plain text and HTML parts from the email body."""

        if not self.msg:
            return

        body_plain = ""
        body_html = ""

        if self.msg.is_multipart():
            for part in self.msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))

                if "attachment" in content_disposition:
                    continue

                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    text = payload.decode(charset, errors="replace")

                    if content_type == "text/plain":
                        body_plain += text + "\n"
                    elif content_type == "text/html":
                        body_html += text + "\n"
        else:
            content_type = self.msg.get_content_type()
            payload = self.msg.get_payload(decode=True)
            if payload:
                charset = self.mgs.get_content_charset() or "utf-8"
                text = payload.decode(charset, errors="replace")

                if content_type == "text/plain":
                    body_plain = text
                elif content_type == "text/html":
                    body_html = text

        self.extracted_data["body_plain"] = body_plain.strip()
        self.extracted_data["body_html"] = body_html.strip()

    def extract_urls(self):
        """Extracts all URLs and detects mismatched (phishing) HTML links."""

        all_urls = set()
        general_pattern = r"https?://[^\s<>\"']+"

        if self.extracted_data.get("body_plain"):
            all_urls.update(
                re.findall(general_pattern, self.extracted_data["body_plain"])
            )

        if self.extracted_data.get("body_html"):
            all_urls.update(
                re.findall(general_pattern, self.extracted_data["body_html"])
            )

        clean_urls = []
        ignored_extensions = (
            ".jpg",
            ".jpeg",
            ".png",
            ".gif",
            ".css",
            ".svg",
            ".woff",
            ".woff2",
            ".ico",
        )

        ignored_domains = [
            "fonts.googleapis.com",
            "fonts.gstatic.com",
            "www.w3.org",
            "schemas.microsoft.com",
            "purl.org",
        ]

        for url in all_urls:
            try:

                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                path = parsed.path.lower()

                if domain in ignored_domains:
                    continue

                if path.endswith(ignored_extensions):
                    continue

                clean_urls.append(url)

            except Exception:

                continue

        self.extracted_data["urls"] = clean_urls

        mismatch_pattern = (
            r"(?i)href=[\"'](https?://[^\"']+)[\"'][^>]*>\s*(https?://(?!\1)[^<]+)"
        )

        mismatched_links = []
        if self.extracted_data.get("body_html"):
            matches = re.findall(mismatch_pattern, self.extracted_data["body_html"])
            for real_link, fake_text in matches:
                mismatched_links.append(
                    {"hidden_target": real_link, "visible_text": fake_text}
                )

        self.extracted_data["mismatched_links"] = mismatched_links

    def extract_attachments(self):
        """Extracts attachments securely in-memory and calculates SHA-256 hashes."""
        if not self.msg:
            return

        for part in self.msg.walk():

            content_type = part.get_content_maintype()
            if content_type == "multipart":
                continue

            if content_type == "text" and part.get_filename() is None:
                continue

            filename = part.get_filename()

            if filename:

                payload = part.get_payload(decode=True)

                if payload:

                    file_hash = hashlib.sha256(payload).hexdigest()

                    self.extracted_data["attachments"].append(
                        {
                            "filename": filename,
                            "hash_sha256": file_hash,
                            "size_bytes": len(payload),
                        }
                    )

    def get_results(self):
        """Returns the dictionary with extracted data."""
        return self.extracted_data
