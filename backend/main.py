import sys
from core.parser import EMLParser
from services.vt_scanner import VTScanner
from services.ai_analyzer import AIAnalyzer


def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <path_to_eml_file>")
        return

    eml_path = sys.argv[1]
    print(f"[*] Starting triage for: {eml_path}\n")

    parser = EMLParser(eml_path)
    scanner = VTScanner()
    ai = AIAnalyzer()

    print("[*] Parsing email headers and body...")
    parser.extract_headers()
    parser.extract_body()

    print("[*] Extracting and filtering URLs...")
    parser.extract_urls()

    parsed_results = parser.get_results()
    urls_to_scan = parsed_results.get("urls", [])

    if not urls_to_scan:
        print("[+] No URLs found for scanning after noise reduction.")
    else:

        print(f"[+] Found {len(urls_to_scan)} clean URLs to check.\n")
        print("[*] Querying VirusTotal API...")
        for url in urls_to_scan:
            print(f"    Checking: {url}")
            vt_report = scanner.get_url_report(url)

            if vt_report.get("status") == "Success":
                malicious_count = vt_report["malicious"]
                if malicious_count > 0:
                    print(
                        f"    🚨 [ALERT] Malicious URL! Detections: {malicious_count}"
                    )
                else:
                    print("    ✅ Clean (0 detections)")
            else:
                print(
                    f"    Status: {vt_report.get('status') or vt_report.get('error')}"
                )
            print("-" * 20)

    print("\n[*] Extracting and hashing attachments...")
    parser.extract_attachments()

    parsed_results = parser.get_results()
    attachments = parsed_results.get("attachments", [])

    if not attachments:
        print("[+] No attachments found in this email.")
    else:
        print(f"[+] Found {len(attachments)} attachments. Querying VirusTotal...")
        for att in attachments:
            filename = att["filename"]
            file_hash = att["hash_sha256"]

            print(f"    Checking file: {filename}")
            print(f"    Hash: {file_hash[:15]}... (truncated)")

            vt_report = scanner.get_hash_report(file_hash)

            if vt_report.get("status") == "Success":
                malicious_count = vt_report["malicious"]
                if malicious_count > 0:
                    print(
                        f"    🚨 [ALERT] Malicious File! Detections: {malicious_count}"
                    )
                else:
                    print("    ✅ Clean (0 detections)")
            else:
                print(
                    f"    Status: {vt_report.get('status') or vt_report.get('error')}"
                )
            print("-" * 20)

    print("\n[*] Initializing Local AI (Phi-3) for Social Engineering analysis...")
    body_plain = parsed_results.get("body_plain", "")

    if not body_plain:
        print("[+] No readable plain text found for AI analysis.")
    else:
        print(
            "    Analyzing text for manipulation tactics (this may take a few seconds)..."
        )
        ai_report = ai.analyze_text(body_plain)

        if "error" in ai_report:
            print(f"    🚨 AI Error: {ai_report['error']}")
        else:
            verdict = ai_report.get("ai_verdict", "Unknown")

            if verdict == "Malicious":
                print(f"    🧠 AI Verdict: 🔴 {verdict}")
            elif verdict == "Suspicious":
                print(f"    🧠 AI Verdict: 🟡 {verdict}")
            else:
                print(f"    🧠 AI Verdict: 🟢 {verdict}")

            print(f"    ⚠️ Urgency Level: {ai_report.get('urgency_level')}/10")
            print(f"    💰 Financial Pressure: {ai_report.get('financial_pressure')}")

            tactics = ai_report.get("manipulation_tactics", [])
            if tactics:
                print(f"    🎯 Tactics Detected: {', '.join(tactics)}")

            print(f"    📝 Reason: {ai_report.get('brief_reason')}")
            print("-" * 20)


if __name__ == "__main__":
    main()
