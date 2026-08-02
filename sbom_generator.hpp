/**
 * Aegis Prime — SBOM Generator (CycloneDX 1.5 + SPDX 2.3)
 * 
 * Produces cryptographically signed Software Bills of Materials.
 * CycloneDX is the format required by SARB, FSCA, and the EU Cyber Resilience Act.
 * 
 * Author: Nvula Bontes <nvula@aegisprime.io>
 * Company: Aegis Prime (Pty) Ltd
 * Copyright: (c) 2026 Aegis Prime (Pty) Ltd. All rights reserved.
 * CONFIDENTIAL — Do not distribute source code.
 */

#pragma once

#include <string>
#include <vector>
#include <filesystem>
#include <functional>
#include <nlohmann/json.hpp>

namespace aegis::sbom {

// ─── Component: one dependency entry in the SBOM ─────────────────────────────
struct Component {
    std::string type;           // "library", "framework", "application"
    std::string name;
    std::string version;
    std::string purl;           // Package URL (purl.github.io spec)
    std::string ecosystem;      // "npm", "pip", "maven", "cargo", "conan"
    std::string license_id;     // SPDX identifier e.g. "MIT", "Apache-2.0"
    std::string description;
    std::string hash_sha256;    // Hash of the package archive if available
    bool        is_direct = false; // Direct dep vs transitive
    
    // Convert to CycloneDX JSON component object
    nlohmann::json to_cyclonedx() const;
    // Convert to SPDX package entry
    nlohmann::json to_spdx() const;
};

// ─── VulnerabilityFinding: CVE linked to a component ─────────────────────────
struct VulnerabilityFinding {
    std::string component_name;
    std::string component_version;
    std::string cve_id;         // e.g. "CVE-2021-44228" (Log4Shell)
    std::string cvss_score;     // e.g. "10.0"
    std::string severity;       // "CRITICAL", "HIGH", "MEDIUM", "LOW"
    std::string description;
    std::string fix_version;    // Version that fixes it (empty = no fix yet)
    std::string published_date;
};

// ─── SbomDocument: the full signed SBOM output ───────────────────────────────
struct SbomDocument {
    std::string serial_number;       // UUID for this SBOM
    std::string timestamp;           // ISO8601
    std::string project_name;
    std::string project_version;
    std::string tool_vendor;         // "Aegis Prime (Pty) Ltd"
    std::string tool_version;        // "1.0.0"
    std::vector<Component> components;
    std::vector<VulnerabilityFinding> vulnerabilities;
    std::string merkle_signature;    // HMAC-SHA256 signature over the document
    
    // Export in CycloneDX 1.5 JSON format (SARB preferred)
    nlohmann::json to_cyclonedx_json() const;
    // Export in SPDX 2.3 JSON format (EU CRA preferred)
    nlohmann::json to_spdx_json() const;
    // Export as human-readable audit report
    std::string to_audit_report() const;
    
    // Has any CRITICAL or HIGH vulnerability been found?
    bool has_critical_findings() const;
    int critical_count() const;
    int high_count() const;
};

// ─── Progress callback for CLI output ────────────────────────────────────────
using ProgressCallback = std::function<void(const std::string& message)>;

// ─── SbomGenerator: the main scanning engine ─────────────────────────────────
class SbomGenerator {
public:
    explicit SbomGenerator(const std::string& signing_key = "");
    
    // Set a callback for real-time progress updates to CLI
    void set_progress_callback(ProgressCallback cb) { progress_ = cb; }
    
    // Main scan function: scans a project root and returns a complete SBOM
    SbomDocument scan(const std::filesystem::path& project_root,
                      const std::string& project_name = "",
                      const std::string& project_version = "");
    
    // Enable/disable CVE scanning (requires internet for OSV/NVD lookup)
    void set_cve_scanning(bool enabled) { cve_scanning_ = enabled; }

private:
    std::string signing_key_;
    bool        cve_scanning_ = true;
    ProgressCallback progress_;
    
    // Package manager extractors
    void extract_npm(const std::filesystem::path& root, std::vector<Component>& out);
    void extract_pip(const std::filesystem::path& root, std::vector<Component>& out);
    void extract_maven(const std::filesystem::path& root, std::vector<Component>& out);
    void extract_gradle(const std::filesystem::path& root, std::vector<Component>& out);
    void extract_cargo(const std::filesystem::path& root, std::vector<Component>& out);
    void extract_cmake(const std::filesystem::path& root, std::vector<Component>& out);
    void extract_nuget(const std::filesystem::path& root, std::vector<Component>& out);
    void extract_go_mod(const std::filesystem::path& root, std::vector<Component>& out);
    
    // CVE lookup via OSV.dev API (free, no key required)
    std::vector<VulnerabilityFinding> check_osv(const Component& comp);
    
    // Cryptographic signing (HMAC-SHA256)
    std::string sign_document(const std::string& json_payload);
    
    // Helpers
    std::string generate_uuid();
    std::string get_iso8601_now();
    std::string build_purl(const std::string& ecosystem, const std::string& name,
                           const std::string& version);
    
    void log(const std::string& msg);
};

} // namespace aegis::sbom
