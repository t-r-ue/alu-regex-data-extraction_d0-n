from pathlib import Path
import re
import os
import json
import sys
import unittest

#reconfiguring terminal output to utf-8
if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

#Regex patterns constants
#1. Email pattern
EMAIL_PATTERN = re.compile(r"\b\w[a-zA-Z0-9.-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")

#2. Credit Card pattern
CC_PATTERN = re.compile(r"\b(?:\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}|\d{4}[- ]?\d{6}[- ]?\d{5})\b")

#3. URL pattern
URL_PATTERN = re.compile(r"\bhttps?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)")

#4. Phone number pattern (Rwanda and USA)
PHONE_PATTERN = re.compile(r"(?<!\w)(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b|(?<!\w)(?:\+250[-.\s]?|0)7[2389]\d[-.\s]?\d{3}[-.\s]?\d{3}\b")

#5. SQL Injection
SQL_INJECTION = re.compile(r"--|/\*|or\s+1\s*=\s*1", re.IGNORECASE)

#6. Cross-Site Scripting (XSS):
XSS = re.compile(r"<script|<iframe|javascript:|onerror=|onload=", re.IGNORECASE)

#7. Traversal
TRAV_PATTERN = re.compile(r"\.\./|\.\.\\")

#Classifying emails
def classify_email(email: str) -> str: 

    email_lower = email.lower() #in case the logs contains uppercase emails
    if email_lower.endswith('@alueducation.com'):
        return 'ALU Staff'
    
    elif email_lower.endswith('@alumni.alueducation.com'):
        return 'ALU Alumni'

    elif email_lower.endswith('@alustudent.com'):
        return 'ALU Student'
    else:
        return 'General email'

#credit card validator/Luhn algorithm
def luhn(credit_card: str) -> bool:
    digits = [int(c) for c in credit_card if c.isdigit()] # extracting only numbers from the credit card, in case it contains hyphens or spaces

    #checking the standanrd credit card length range, 13-19 digits
    if not (13 <= len(digits) <= 19):
        return False

    #checking for fraud credit card numbers which are all same number
    if len(set(digits)) == 1:
        return False

    digits.reverse()

    #luhn algorithm
    for i in range(1, len(digits), 2):
        doubled = digits[i] * 2
        if doubled > 9:
            doubled -= 9
        digits[i] = doubled

    return sum(digits) % 10 == 0


#SECURITY FEATURES

# 1. Threat detection
def detect_threat(text: str) -> list[str]:
    threats = []
    if SQL_INJECTION.search(text):
        threats.append("SQL Injection threat detected")  # SQL INJECTION

    if XSS.search(text):
        threats.append("Cross Site Scripting threat detected") # Cross Site Scripting

    if TRAV_PATTERN.search(text):
        threats.append("Path Traversal threat detected") # Path Traversal

    return threats

# 2. Email Masking
def mask_email(email: str) -> str:
    local_part, domain_part = email.split('@')

    if len(local_part) <= 2:
        masked_local = "*" * len(local_part)
    else:
        middle_mask = "*" * (len(local_part) - 2)
        masked_local = local_part[0] + middle_mask + local_part[-1]
    
    return masked_local + "@" + domain_part

# 3. Credit card masking
def mask_cc(credit_card: str) -> str:
    masked_char = []
    digit_count = 0

    for x in reversed(credit_card):
        if x.isdigit():
            digit_count += 1
            if digit_count > 4:
                masked_char.append("X")
            else:
                masked_char.append(x)
        else:
            masked_char.append(x)
            
    masked_char.reverse()
    return "".join(masked_char)

# Log processing
def process_logs(input_path: str):
    def overlaps(start: any, end: any, occupied_range: any) -> bool:
        for s, e in occupied_range:
            if max(start, s) < min(end, e):  #checks if two ranges overlap
                return True
        return False

    with open(input_path, 'r', encoding='utf-8') as f:
        lines = f.readlines() 
        report = {
            "summary": {
                "total_lines": len(lines),
                "emails_found": 0,
                "cards_found": 0,
                "urls_found": 0,
                "phones_found": 0,
                "threats_found": 0
            },
            "extracted_data": {
                "emails": [],
                "credit_cards": [],
                "urls": [],
                "phone_numbers": []
            },
            "threats": []
        }

    for line_num, line in enumerate(lines, 1):
        occupied_range = []
        threat_line = detect_threat(line)
        for threat in threat_line:
            report["threats"].append({
                "line": line_num,
                "threat": threat,
                "details": line.strip() 
            })
            report["summary"]["threats_found"] += 1   

        for email in EMAIL_PATTERN.finditer(line):
            email_str = email.group()
            start, end = email.span()

            if overlaps(start, end, occupied_range): continue

            report["extracted_data"]["emails"].append({
                "raw": email_str,
                "masked": mask_email(email_str),
                "classification": classify_email(email_str),
                "line": line_num
            })
            report["summary"]["emails_found"] += 1
            occupied_range.append((start, end))
        
        for c_card in CC_PATTERN.finditer(line):
            card = c_card.group()
            start, end = c_card.span()

            if overlaps(start, end, occupied_range): continue

            report["extracted_data"]["credit_cards"].append({
                "raw": card,
                "masked": mask_cc(card),
                "luhn_valid": luhn(card),
                "line": line_num
            })
            report["summary"]["cards_found"] += 1
            occupied_range.append((start, end))

        for url in URL_PATTERN.finditer(line):
            url_str = url.group()
            start, end = url.span()

            if overlaps(start, end, occupied_range): continue
            
            report["extracted_data"]["urls"].append({
                "url": url_str,
                "line": line_num
            })
            report["summary"]["urls_found"] += 1
            occupied_range.append((start, end))

        for phone in PHONE_PATTERN.finditer(line):
            phone_num = phone.group()
            start, end = phone.span()

            if overlaps(start, end, occupied_range): continue
            
            report["extracted_data"]["phone_numbers"].append({
                "num": phone_num,
                "line": line_num
            })
            report["summary"]["phones_found"] += 1
            occupied_range.append((start, end))
            
    return report

class TestSanitizer(unittest.TestCase):
    def test_email_classification(self):
        self.assertEqual(classify_email("admin@alueducation.com"), "ALU Staff")
        self.assertEqual(classify_email("john@alumni.alueducation.com"), "ALU Alumni")
        self.assertEqual(classify_email("d.marume@alustudent.com"), "ALU Student")
        self.assertEqual(classify_email("someone@gmail.com"), "General email")

    def test_email_masking(self):
        self.assertEqual(mask_email("admin.lecturer@alueducation.com"), "a************r@alueducation.com")
        self.assertEqual(mask_email("ab@gmail.com"), "**@gmail.com")

    def test_luhn(self):
        self.assertTrue(luhn("4111-1111-1111-1111"))
        self.assertFalse(luhn("4111-1111-1111-1112"))

    def test_cc_masking(self):
        self.assertEqual(mask_cc("4111-1111-1111-1111"), "XXXX-XXXX-XXXX-1111")
        self.assertEqual(mask_cc("3782 822463 10005"), "XXXX XXXXXX X0005")

    def test_threat_detection(self):
        threats = detect_threat("SELECT * FROM users WHERE email='admin@alueducation.com' OR 1=1 --")
        self.assertIn("SQL Injection threat detected", threats)
        
        threats_xss = detect_threat("<script>alert('XSS')</script>")
        self.assertIn("Cross Site Scripting threat detected", threats_xss)
        
        threats_trav = detect_threat("../../../../etc/passwd")
        self.assertIn("Path Traversal threat detected", threats_trav)

def run_tests():
    suite = unittest.TestLoader().loadTestsFromTestCase(TestSanitizer)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    if not result.wasSuccessful():
        sys.exit(1)

def main():
    if "--test" in sys.argv:
        print("Running self-tests...")
        run_tests()
        return

    if "--input" in sys.argv and "--output" in sys.argv:
        try:
            # Get indices of the files in sys.argv
            input_idx = sys.argv.index("--input") + 1
            output_idx = sys.argv.index("--output") + 1
            
            input_path = sys.argv[input_idx]
            output_path = sys.argv[output_idx]
            
            print(f"[*] Processing logs from: {input_path}")
            report = process_logs(input_path)
            
            # Create output directory if it doesn't exist
            output_dir = os.path.dirname(output_path)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)

            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=4)
                
            print(f"[+] Sanitized report saved to: {output_path}\n")
            
            # Print SOC-like Dashboard
            print("=" * 65)
            print("         🛡️  SOC ANALYST SECURITY LOG MONITOR SUMMARY 🛡️")
            print("=" * 65)
            print(f"Lines Processed: {report['summary']['total_lines']}")
            print("-" * 65)
            print(f"📧 Emails Found:       {report['summary']['emails_found']}")
            print(f"💳 Credit Cards Found:  {report['summary']['cards_found']}")
            print(f"🔗 URLs Found:          {report['summary']['urls_found']}")
            print(f"📞 Phone Numbers Found: {report['summary']['phones_found']}")
            print(f"🚨 Threats Blocked:     {report['summary']['threats_found']}")
            print("=" * 65)
            
            if report["summary"]["threats_found"] > 0:
                print("⚠️  DETECTED LOG INCIDENTS:")
                for incident in report["threats"]:
                    print(f"  [LINE {incident['line']}] - {incident['threat']}")
                    print(f"    Payload: {incident['details']}")
                print("=" * 65)
            else:
                print("✅ STATUS: System clean. No threats detected.")
                print("=" * 65)

        except (ValueError, IndexError) as e:
            print(f"Error: Please provide correct paths after --input and --output. Details: {e}")
    else:
        print("Usage:")
        print("  python src/main.py --test")
        print("  python src/main.py --input <input_file> --output <output_file>")

if __name__ == "__main__":
    main()