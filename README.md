<h1 align="center">FUFP — File Upload Fuzz Pack</h1>
<p align="center">
  🇺🇸 <b>English</b> |
  🇪🇸 <a href="README_ES.md">Español</a>
</p>

<h3 align="center">FUFP (File Upload Fuzz Pack) is a curated personal collection of files designed to test, fuzz, and analyze file upload mechanisms in web applications.</h3>

It focuses on common file upload vulnerabilities such as improper extension filtering, MIME-type confusion, magic byte bypasses, double extensions, encoding tricks, and server-side execution risks.

> ⚠️ **For authorized security testing only.**

---

## 🎯 Purpose

File upload functionalities are a frequent attack surface in web applications.  
FUFP helps security testers, bug bounty hunters, and developers:

- Identify weak file type validation
- Test blacklist / whitelist implementations
- Detect MIME-type trust issues
- Discover extension parsing inconsistencies
- Assess server-side execution risks
- Evaluate archive handling and extraction behavior

FUFP is intended for **manual testing**, **automation**, and **educational purposes**.

---

## 📁 Directory Structure

```

FUFP/
├── fufp.py              # More information about this file below
├── images/              # Image formats, polyglots, EXIF & header tricks
├── documents/           # Text and document file formats
├── scripts/             # Client-side and scripting languages
├── web/                 # Web-related formats (HTML, SVG, XML, CSS)
├── server_side/         # Server-executed file extensions
├── bypass_techniques/   # Extension & encoding bypass attempts
├── binaries/            # Executable-like binary formats
├── archives/            # Compressed and container files
├── server_configs/      # Configuration-related files
├── traversal_tests/     # Path traversal payload references
├── magic_bytes/         # Header-based file type confusion
├── mime_confusion/      # MIME-type mismatch cases
├── oversized_files/     # Size-based and timing-related tests
├── LICENSE
├── README.md
└── README_ES.md

```

---
## FUFP Generator Script (_*fufp.py*_)

FUFP includes a **fully automated Python generator** that creates the entire file upload fuzzing pack from scratch in a safe, reproducible, and controlled way.

The generator is designed with **cross-platform filesystem limitations** in mind (Windows/Linux/macOS) and avoids creating files that cannot exist on real filesystems (such as raw null bytes in filenames or forbidden characters). Instead, those edge cases are represented through **accurate file contents and descriptive text files**, ensuring realism without breaking portability.

### Usage
<img width="601" height="202" alt="image" src="https://github.com/user-attachments/assets/b9fdf8ca-347d-4205-bee4-6e221850810e" />

### Basic usage
```bash
python fufp.py
````

* Generates the full File Upload Fuzz Pack
* Output directory: `FUFP`
* Safe mode (no active payloads)
* Minimal console output

---

### Common options explained

* **`-o, --output OUTPUT`**
  Choose where the FUFP directory will be created.
  Example:

  ```bash
  python fufp.py -o my_fufp_pack
  ```

* **`-v, --verbose`**
  Shows every file as it is created. Useful to understand what the generator is doing.

  ```bash
  python fufp.py -v
  ```

* **`-q, --quiet`**
  Minimal output. Overrides verbose mode if both are set.

  ```bash
  python fufp.py -q
  ```

* **`--enable-dangerous`** ⚠️
  Enables active payloads such as `eval`, `system`, and `exec`.
  **Only use this for authorized security testing.**

  ```bash
  python fufp.py --enable-dangerous
  ```

* **`--version`**
  Displays the generator version and exits.

  ```bash
  python fufp.py --version
  ```

### Recommended usage

For most users:

```bash
python fufp.py
```

For debugging or learning how (or what) files are generated:

```bash
python fufp.py -v
```

For Bug Bounty addicts (lol):

```bash
python genfufp.py -o FUFP-PREMIUM -v --enable-dangerous
```

### Key characteristics

- **Deterministic generation**  
  Every run produces the same structured output, making results reproducible and easy to version-control.

- **Strict text vs binary separation**  
  Files are written using the correct mode (`text` or `binary`) to accurately simulate real-world uploads.

- **Real magic bytes**  
  Binary formats (PNG, JPEG, PDF, ZIP, PE, ELF, etc.) include valid magic headers to test content-based validation.

- **Safe by default**  
  Potentially dangerous payloads (e.g. `system`, `exec`, `eval`) are **disabled by default** and replaced with inert markers.

- **Optional dangerous payloads**  
  Advanced testers can explicitly enable active payloads via a command-line flag, making intent clear and explicit.

- **No external dependencies**  
  Uses only the Python standard library, ensuring easy execution on most systems.

### Purpose

This script exists to:
- Remove the manual effort of crafting hundreds of test files
- Ensure consistency across testing environments
- Allow easy regeneration, auditing, and sharing of the fuzzing pack

The generator itself is **not an exploitation tool** — it is a controlled file factory intended to support **authorized security testing and research**.

---

## 🧪 What This Pack Tests

### ✔ Extension Filtering
- Double extensions (`.php.jpg`)
- Case variations (`.PhP`, `.PHP`)
- Trailing dots (`.php.`)
- Multiple dots (`.php..`, `.php...`)
- Alternate PHP extensions (`.phtml`, `.php5`, `.phar`, etc.)

### ✔ MIME-Type Validation
- Content-Type mismatches
- Trust in client-supplied MIME headers
- Server-side MIME sniffing issues

### ✔ Magic Bytes
- Valid file headers with dangerous extensions
- Executable files disguised as images or documents
- Polyglot-style payloads

### ✔ Archive Handling
- ZIPs containing scripts or config files
- Extraction and validation behavior
- Nested or misleading archive contents

### ✔ Server Execution Risks
- PHP, ASP, JSP, CFML, and related extensions
- Misconfigured upload directories
- Improper execution permissions

### ✔ Size & Resource Handling
- Oversized uploads
- Timeout simulation
- Metadata-heavy files

> Please note that this repository is github-safe, some test files are more dangerous, thats why the --enable-dangerous flag exist in the generation file (more info above)
> 
---

## 🚀 Usage

### Manual Testing
1. Select relevant files from FUFP
2. Upload them via the target application's upload functionality
3. Observe:
   - Server responses
   - File acceptance or rejection
   - Renaming behavior
   - Execution or rendering behavior

### Automated Testing
FUFP can be integrated into:
- Custom fuzzing scripts
- CI pipelines
- Burp / ZAP upload testing workflows

---

## 🔐 Safety & Scope

- Files are **non-destructive**
- Executables contain **headers only**, not real malware
- Dangerous payloads are disabled by default
- Designed to avoid accidental harm

Still, **never upload these files to systems you do not own or have explicit permission to test**.

---

## ⚠️ Legal Disclaimer

This project is provided for **educational and authorized security testing purposes only**.

The author is **not responsible for misuse**, damage, or illegal activity resulting from the use of this repository.

By using FUFP, you agree to comply with all applicable laws and regulations.

---

## 🧠 Who Is This For?

- Bug bounty hunters
- Penetration testers
- Security researchers
- Web developers testing upload defenses
- Students learning web security

---

## 📌 Notes

- This is **not a malware repository**
- No real exploits are shipped
- Focus is on **detection**, **validation**, and **defensive testing**

---
## ⭐ Contributing

Pull requests are welcome if they:
- Add new relevant file types
- Improve bypass coverage
- Keep the pack safe and ethical

---
Made with <3 by URDev
