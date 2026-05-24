# Log Sanitizer & Threat Detector

An advanced regular-expression-based security tool that parses messy, production-style system logs, extracts key structured identifiers, flags injection and traversal threats, and masks PII (Personally Identifiable Information) before generating security reports.

Solution for the **Data Extraction & Secure Validation Assignment (Regex Onboarding Hackathon)**.

---

## Project Structure

The project conforms to the required directory structure:

```text
alu-regex-data-extraction_d0-n/
├── input/
│   └── raw-text.txt          # Messy raw system logs used as input
├── src/
│   └── main.py              # Main Python script (contains regexes, logic, and tests)
├── output/
│   └── sample-output.json    # Sanitized structured JSON security report
└── README.md                 # Project documentation and execution instructions
```

---

## How to Run the Program

### 1. Prerequisites
Ensure you have Python 3.x installed. You can check your version by running:
```powershell
python --version
```

### 2. Run Built-in Self-Tests
The script features a test module to assert regex accuracy, Luhn algorithms, threat blockers, and PII masking correctness.
```powershell
python src/main.py --test
```

### 3. Parse Log Files
To process the sample logs inside `input/raw-text.txt` and output the sanitized JSON to `output/sample-output.json`:
```powershell
python src/main.py --input input/raw-text.txt --output output/sample-output.json
```

---

## Regex Design & Explanations

### 1. Emails
*   **Pattern**: `\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b`
*   **Explanation**: Matches standard email structures. Uses word boundaries (`\b`) to ensure it doesn't match partial structures.
*   **ALU Validation**: Uses Python string matching to classify emails into:
    *   `@alueducation.com` $\rightarrow$ **ALU Official**
    *   `@alumni.alueducation.com` $\rightarrow$ **ALU Alumni**
    *   `@si.alueducation.com` $\rightarrow$ **ALU Student / SI**
    *   Any other domains $\rightarrow$ **General Email**

### 2. Credit Cards (Visa, MC, Amex, Discover)
*   **Pattern**: `\b(?:\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}|\d{4}[-\s]?\d{6}[-\s]?\d{5})\b`
*   **Explanation**:
    *   `\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}`: Matches standard 16-digit cards (Visa, MasterCard, Discover) grouped in blocks of 4 separated by optional spaces or hyphens.
    *   `\d{4}[-\s]?\d{6}[-\s]?\d{5}`: Matches 15-digit American Express cards (4-6-5 digit grouping).
*   **Luhn Check**: Extracted cards undergo a mathematical validation using the Luhn Algorithm. Malformed cards (e.g. failing the checksum) are blocked and flagged.

### 3. URLs
*   **Pattern**: `\bhttps?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)`
*   **Explanation**: Matches standard `http://` or `https://` URLs, tracking optional domains, ports, query strings, and path routes.

### 4. Phone Numbers
*   **Pattern**:
    ```regex
    (?<!\w)(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b|\(?<!\w)(?:\+250[-.\s]?|0)7[2389]\d[-.\s]?\d{3}[-.\s]?\d{3}\b
    ```
*   **Explanation**:
    *   **Negative Lookbehinds (`(?<!\w)`)**: Placed at the start of the patterns to allow phone numbers beginning with punctuation (like `+` or `(`) to match fully without being truncated by strict word boundaries (`\b`).
    *   **Group 1 (International/US)**: Matches standard formats with country codes and mandatory area separators (e.g., `+1-555-876-5432`, `(123) 456-7890`).
    *   **Group 2 (East African/Rwandan Mobile)**: Matches Rwandan codes (+250 or 0) followed by 72, 73, 78, or 79 mobile lines (e.g., `+250 788 123 456`, `0788123456`).

---

## Security & PII Protection Features

1.  **PII Obfuscation (Masking)**:
    *   **Credit Cards**: Replaces all but the last 4 digits with `X` (preserving formatting layout, e.g., `XXXX-XXXX-XXXX-1111`) to prevent card numbers from leaking in report files or screen logs.
    *   **Emails**: Obfuscates the local mailbox part (e.g., `d***n@alueducation.com`).
2.  **Hostile Injection Blocking**:
    Tokens extracted are validated against signature matches for:
    *   **SQL Injection (SQLi)**: Filters out SQL comment hyphens (`--`), or boolean bypasses (e.g. `' OR 1=1 --`).
    *   **Cross-Site Scripting (XSS)**: Filters out HTML tags, script nodes (`<script>`), and JS event handlers (`onload`, `onerror`).
    *   **Directory Traversal**: Blocks traversal payloads (`../` or `..\`) attempting local system breaches.
3.  **Span-Exclusion Match Routing**:
    Ensures regex matches do not overlap. This stops phone number parsers from matching subgroups inside credit cards (e.g. extracting the first 12 digits of a Visa card as a phone number).
