import re
import os
from urllib.parse import urlparse

class PhishGuard:
    def __init__(self):
        self.risk_score = 0
        self.report_entries = []
        self.load_patterns()

    def load_patterns(self):
        self.suspicious_phrases = [
            "your account has been", "immediate action required", "verify your identity",
            "suspicious activity", "password reset", "update billing", "payment declined",
            "click here to login", "secure your account now"
        ]
        self.urgency_keywords = [
            "urgent", "immediately", "within 24 hours", "today", "now", "asap",
            "account will be suspended", "final notice", "last warning"
        ]
        self.suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".info", ".online"]
        self.homoglyph_pairs = {
            'a': ['а', 'ɑ'], 'o': ['о', 'ο'], 'e': ['е'], 'i': ['і', '1'],
            'l': ['1', 'І'], '0': ['Ο', 'о'], 's': ['ѕ'], 'c': ['с']
        }

    def add_indicator(self, description: str, points: int):
        self.risk_score += points
        self.report_entries.append(f"• {description} (+{points})")

    def detect_homoglyph(self, text: str):
        found = []
        for legit, fakes in self.homoglyph_pairs.items():
            for fake in fakes:
                if fake in text:
                    found.append(f"'{fake}' → '{legit}'")
        return found

    def analyze_url(self, url: str):
        self.report_entries.append(f"\nAnalyzed URL: {url}")
        
        try:
            parsed = urlparse(url if url.startswith("http") else "https://" + url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            query = parsed.query.lower()
        except:
            self.add_indicator("Malformed or invalid URL format", 30)
            return

        # Suspicious TLD
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                self.add_indicator(f"Suspicious TLD: {tld}", 35)

        # Very long URL
        if len(url) > 80:
            self.add_indicator("Unusually long URL", 15)

        # Keywords in domain or path
        for phrase in self.suspicious_phrases + self.urgency_keywords:
            if phrase in domain or phrase in path or phrase in query:
                self.add_indicator(f"Suspicious keyword in URL: '{phrase}'", 20)

        # Homoglyph in domain
        homoglyphs = self.detect_homoglyph(domain)
        if homoglyphs:
            self.add_indicator(f"Homoglyph(s) in domain: {', '.join(homoglyphs)}", 40)

        # Suspicious parameters
        if "redirect" in query or "next=" in query or "url=" in query or "login" in query:
            self.add_indicator("Suspicious redirect / login parameter", 25)

    def analyze_email_text(self, text: str):
        self.report_entries.append("\nAnalyzed email text snippet:")

        lines = text.splitlines()
        for line in lines[:15]:  # limit to beginning of email
            line_lower = line.lower()

            # Urgency language
            for word in self.urgency_keywords:
                if word in line_lower:
                    self.add_indicator(f"Urgency phrase: '{word}'", 18)

            # Phishing phrases
            for phrase in self.suspicious_phrases:
                if phrase in line_lower:
                    self.add_indicator(f"Typical phishing phrase: '{phrase}'", 22)

        # Links in text
        urls = re.findall(r'(https?://[^\s]+)', text)
        if urls:
            self.report_entries.append(f"Found {len(urls)} link(s) in email")
            for url in urls[:3]:
                self.analyze_url(url)   # reuse URL analyzer

    def calculate_risk_level(self):
        self.risk_score = min(self.risk_score, 100)
        if self.risk_score >= 70:
            return "HIGH RISK – strong phishing indicators"
        elif self.risk_score >= 40:
            return "MEDIUM RISK – suspicious elements present"
        else:
            return "LOW RISK – no major red flags detected"

    def generate_verdict(self):
        verdict = self.calculate_risk_level()
        self.report_entries.append(f"\n{'═'*60}")
        self.report_entries.append(f"FINAL VERDICT: {verdict}")
        self.report_entries.append(f"Risk score: {self.risk_score}/100")
        self.report_entries.append(f"{'═'*60}")

    def print_report(self):
        print("\n".join(self.report_entries))

    def save_report(self, filename="phishguard_report.txt"):
        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(self.report_entries))
        print(f"\nReport saved → {os.path.abspath(filename)}")

    def run_scanner(self):
        print("\nWhat would you like to scan?")
        print("1 = URL / domain")
        print("2 = Email body text")
        choice = input("→ ").strip()

        scanner = PhishGuard()  # fresh instance per scan

        if choice == "1":
            url = input("\nPaste URL or domain: ").strip()
            scanner.analyze_url(url)
        elif choice == "2":
            print("\nPaste email text (press Enter twice to finish):")
            lines = []
            while True:
                line = input()
                if line == "":
                    break
                lines.append(line)
            scanner.analyze_email_text("\n".join(lines))
        else:
            print("Invalid choice.")
            return

        scanner.generate_verdict()
        scanner.print_report()

        if input("\nSave report to file? (y/n): ").lower().startswith('y'):
            scanner.save_report()

def show_menu():
    print("\n" + "═"*60)
    print("          PHISHGUARD – Phishing Scanner Tool")
    print("═"*60)
    print(" 1. Scan URL / Email")
    print(" 2. Exit")
    print("═"*60)

def main_loop():
    print("PhishGuard – Basic phishing detection helper\n")
    while True:
        show_menu()
        choice = input("Choose (1-2): ").strip()
        if choice == "1":
            PhishGuard().run_scanner()
        elif choice == "2":
            print("\nStay vigilant. Goodbye.")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main_loop()