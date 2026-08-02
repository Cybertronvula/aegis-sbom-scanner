/**
 * Aegis Prime SBOM Scanner — CLI Tool
 * 
 * Usage:
 *   aegis scan ./my-project
 *   aegis scan ./my-project --output report.json --format cyclonedx
 *   aegis scan ./my-project --no-cve --output sbom.json
 * The output is a signed CycloneDX JSON + human audit report.
 * 
 * Copyright (c) 2026 Aegis Prime (Pty) Ltd. All rights reserved.
 */

#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>
#include <chrono>
#include "../core/sbom_generator.hpp"

// ─── Uncomment to enable license check in production ─────────────────────────
// #include "../license/license_client.hpp"

namespace fs = std::filesystem;
using namespace aegis::sbom;

// ─── ANSI colours for terminal output ─────────────────────────────────────────
#define RED     "\033[1;31m"
#define GREEN   "\033[1;32m"
#define YELLOW  "\033[1;33m"
#define BLUE    "\033[1;34m"
#define GOLD    "\033[38;5;220m"
#define RESET   "\033[0m"
#define BOLD    "\033[1m"

static void print_banner() {
    std::cout << "\n" << GOLD <<
    "  ╔══════════════════════════════════════════════════════╗\n"
    "  ║         AEGIS PRIME — SBOM Scanner v1.0             ║\n"
    "  ║   Aegis Prime (Pty) Ltd | aegisprime.io             ║\n"
    "  ║   The Trust Infrastructure for the Digital Enterprise║\n"
    "  ╚══════════════════════════════════════════════════════╝\n"
    << RESET << "\n";
}

static void print_usage(const char* prog) {
    std::cout << BOLD << "Usage:" << RESET << "\n";
    std::cout << "  " << prog << " scan <project_dir> [options]\n\n";
    std::cout << BOLD << "Options:" << RESET << "\n";
    std::cout << "  --output <file>       Save CycloneDX JSON output (default: stdout)\n";
    std::cout << "  --report <file>       Save human-readable audit report\n";
    std::cout << "  --format <fmt>        Output format: cyclonedx (default) | spdx\n";
    std::cout << "  --no-cve              Skip CVE vulnerability scanning\n";
    std::cout << "  --name <name>         Override project name\n";
    std::cout << "  --version <ver>       Override project version\n";
    std::cout << "  --signing-key <key>   HMAC signing key (or use AEGIS_SIGNING_KEY env)\n";
    std::cout << "\n" << BOLD << "Examples:" << RESET << "\n";
    std::cout << "  " << prog << " scan ./my-node-app\n";
    std::cout << "  " << prog << " scan /var/app --output sbom.json --report audit.txt\n";
    std::cout << "  " << prog << " scan . --name \"ABSA Mobile Backend\" --version 2.1.0\n\n";
}

int main(int argc, char* argv[]) {
    print_banner();

    // ── License check (enable in production) ─────────────────────────────────
    // auto lic = aegis::AegisLicense::validate();
    // if (!lic.valid) {
    //     std::cerr << RED << "[License Error] " << lic.message << RESET << "\n";
    //     return 1;
    // }

    if (argc < 3 || std::string(argv[1]) != "scan") {
        print_usage(argv[0]);
        return 1;
    }

    // ── Parse arguments ───────────────────────────────────────────────────────
    fs::path project_dir = argv[2];
    std::string output_file, report_file, format = "cyclonedx";
    std::string project_name, project_version;
    std::string signing_key = std::getenv("AEGIS_SIGNING_KEY") ? 
                              std::getenv("AEGIS_SIGNING_KEY") : "";
    bool cve_enabled = true;

    for (int i = 3; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--output"     && i+1 < argc) output_file    = argv[++i];
        else if (arg == "--report"     && i+1 < argc) report_file    = argv[++i];
        else if (arg == "--format"     && i+1 < argc) format         = argv[++i];
        else if (arg == "--name"       && i+1 < argc) project_name   = argv[++i];
        else if (arg == "--version"    && i+1 < argc) project_version = argv[++i];
        else if (arg == "--signing-key"&& i+1 < argc) signing_key    = argv[++i];
        else if (arg == "--no-cve")    cve_enabled = false;
    }

    // ── Validate input ────────────────────────────────────────────────────────
    if (!fs::exists(project_dir)) {
        std::cerr << RED << "[Error] Project directory not found: " 
                  << project_dir << RESET << "\n";
        return 1;
    }

    std::cout << BOLD << "  Scanning: " << RESET << fs::absolute(project_dir) << "\n";
    if (!cve_enabled) std::cout << YELLOW << "  [!] CVE scanning disabled\n" << RESET;

    // ── Run scanner ───────────────────────────────────────────────────────────
    auto t_start = std::chrono::high_resolution_clock::now();

    SbomGenerator gen(signing_key);
    gen.set_cve_scanning(cve_enabled);
    gen.set_progress_callback([](const std::string& msg) {
        std::cout << "  " << msg << "\n";
    });

    SbomDocument sbom = gen.scan(project_dir, project_name, project_version);

    auto t_end = std::chrono::high_resolution_clock::now();
    double elapsed = std::chrono::duration<double>(t_end - t_start).count();

    // ── Summary ───────────────────────────────────────────────────────────────
    std::cout << "\n" << BOLD << "════ SCAN SUMMARY ══════════════════════════════\n" << RESET;
    std::cout << "  Project    : " << sbom.project_name << " v" << sbom.project_version << "\n";
    std::cout << "  Components : " << BOLD << sbom.components.size() << RESET << "\n";

    int crit = sbom.critical_count(), hi = sbom.high_count();
    int total_vulns = (int)sbom.vulnerabilities.size();

    if (total_vulns == 0) {
        std::cout << "  Vulns      : " << GREEN << "0 — No vulnerabilities found" << RESET << "\n";
    } else {
        std::cout << "  Vulns      : " << RED << crit << " CRITICAL" << RESET
                  << " | " << YELLOW << hi << " HIGH" << RESET
                  << " | " << (total_vulns - crit - hi) << " other\n";
    }

    std::cout << "  Signed     : " << (sbom.merkle_signature == "UNSIGNED" ?
                  std::string(YELLOW) + "NO (set AEGIS_SIGNING_KEY)" + RESET :
                  std::string(GREEN)  + "YES" + RESET) << "\n";
    std::cout << "  Time       : " << std::fixed << std::setprecision(2) << elapsed << "s\n";
    std::cout << "  Serial #   : " << sbom.serial_number << "\n";
    std::cout << BOLD << "════════════════════════════════════════════════\n\n" << RESET;

    // ── Output ────────────────────────────────────────────────────────────────
    auto json_out = (format == "spdx") ? sbom.to_spdx_json() : sbom.to_cyclonedx_json();

    if (output_file.empty()) {
        // Pretty-print to stdout if no file specified
        if (output_file.empty() && report_file.empty())
            std::cout << json_out.dump(2) << "\n";
    } else {
        std::ofstream of(output_file);
        of << json_out.dump(2);
        std::cout << GREEN << "  CycloneDX JSON saved: " << output_file << RESET << "\n";
    }

    if (!report_file.empty()) {
        std::ofstream rf(report_file);
        rf << sbom.to_audit_report();
        std::cout << GREEN << "  Audit report saved:   " << report_file << RESET << "\n";
    }

    // ── Exit code: non-zero if critical vulns found ───────────────────────────
    // This lets CI/CD pipelines fail builds automatically on critical findings
    if (crit > 0) {
        std::cout << RED << "\n  [!] Build BLOCKED — " << crit 
                  << " critical vulnerabilities require remediation.\n" << RESET;
        return 2;   // Exit 2 = critical vulns (different from exit 1 = error)
    }

    return 0;
}
