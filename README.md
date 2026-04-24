# 📦 Aegis Prime — SBOM Scanner

**Repository:** `aegis-sbom-scanner` (PUBLIC)  
**Owner:** Nvula Bontes | Aegis Prime (Pty) Ltd  
**Language:** C++20  
**Standard:** CycloneDX 1.5 + SPDX 2.3  
**Regulatory:** SARB Guidance Note 3/2021 · EU Cyber Resilience Act · POPIA

---

## What This Solves

After SolarWinds (2020) and Log4Shell (2021), regulators worldwide now require a **Software Bill of Materials** — a complete, signed inventory of every open-source library in every software product. Most South African banks, hospitals, and enterprises have no idea what is running in their production systems.

Aegis Prime SBOM Scanner solves this in a single command.

---

## What It Does

```
aegis scan ./your-project
```

1. Detects all package managers present (npm, pip, Maven, Go modules, Cargo, NuGet)
2. Extracts every dependency — direct and transitive
3. Queries OSV.dev (free CVE database) for known vulnerabilities
4. Produces a cryptographically signed CycloneDX 1.5 JSON document
5. Generates a human-readable audit report for compliance teams
6. Exits with code `2` if critical CVEs are found (blocks CI/CD pipelines)

---

## Quick Start

```bash
# Build from source
git clone https://github.com/aegisprime/aegis-sbom-scanner
cd aegis-sbom-scanner
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Run
./aegis scan /path/to/your/project

# With output files
./aegis scan ./project \
  --name "ABSA Mobile API" \
  --version "2.1.0" \
  --output sbom.json \
  --report audit_report.txt
```

---

## Example Output

```
╔══════════════════════════════════════════════════════╗
║         AEGIS PRIME — SBOM Scanner v1.0             ║
╚══════════════════════════════════════════════════════╝

  Scanning: /home/user/banking-api
  [npm] Reading package-lock.json...
  [npm] Found 147 packages
  [pip] Reading requirements.txt...
  [pip] Found 23 packages
  Running CVE checks via OSV.dev...

════ SCAN SUMMARY ══════════════════════════════
  Project    : banking-api v2.1.0
  Components : 170
  Vulns      : 3 CRITICAL | 7 HIGH | 12 other
  Signed     : YES
  Time       : 4.21s
  Serial #   : urn:uuid:a3f9...
════════════════════════════════════════════════

  [!] Build BLOCKED — 3 critical vulnerabilities require remediation.
```

---

## Output Formats

| Format | Flag | Use case |
|--------|------|----------|
| CycloneDX 1.5 JSON | `--format cyclonedx` | SARB, FSCA, default |
| SPDX 2.3 JSON | `--format spdx` | EU Cyber Resilience Act |
| Audit report (text) | `--report file.txt` | Board / compliance team |

---

## Dependencies

```bash
# Ubuntu/Debian
sudo apt install libssl-dev libcurl4-openssl-dev cmake build-essential

# macOS
brew install openssl curl cmake

# nlohmann/json — downloaded automatically by CMake
```

---

## CI/CD Integration

```yaml
# GitHub Actions example
- name: Aegis SBOM Scan
  run: |
    ./aegis scan . \
      --output sbom.json \
      --report audit.txt
    # Exit code 2 = critical CVEs found = pipeline blocked
```

---

## Regulatory Coverage

| Regulation | Requirement | Aegis Satisfies |
|-----------|-------------|-----------------|
| SARB Guidance Note 3/2021 | Software inventory for banks | ✅ CycloneDX output |
| EU Cyber Resilience Act | SBOM for CE-marked software | ✅ SPDX + CycloneDX |
| POPIA Section 22 | Security safeguards | ✅ Signed audit trail |
| FSCA IT3 | Third-party software risk | ✅ CVE reporting |

---

## License

This CLI tool is open-source for credibility and developer adoption.  
The commercial enterprise engine (bulk scanning, API, dashboard, CI/CD integration) requires a license.  
Contact: licensing@aegisprime.io

---

**Aegis Prime (Pty) Ltd · Kimberley, Northern Cape · aegisprime.io**  
*The Trust Infrastructure for the Digital Enterprise*
