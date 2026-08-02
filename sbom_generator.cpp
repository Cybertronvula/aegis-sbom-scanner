/**
 * Aegis Prime — SBOM Generator Implementation
 * Copyright (c) 2026 Aegis Prime (Pty) Ltd. All rights reserved.
 */

#include "sbom_generator.hpp"
#include <fstream>
#include <sstream>
#include <regex>
#include <chrono>
#include <iomanip>
#include <random>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <curl/curl.h>

namespace aegis::sbom {

// ─── Helpers ──────────────────────────────────────────────────────────────────
static size_t curl_write(char* ptr, size_t size, size_t nmemb, std::string* data) {
    data->append(ptr, size * nmemb);
    return size * nmemb;
}

static std::string http_get(const std::string& url) {
    std::string response;
    CURL* curl = curl_easy_init();
    if (!curl) return "";
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "AegisPrime-SBOM/1.0");
    curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    return response;
}

static std::string http_post_json(const std::string& url, const std::string& body) {
    std::string response;
    CURL* curl = curl_easy_init();
    if (!curl) return "";
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "AegisPrime-SBOM/1.0");
    curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return response;
}

// ─── Component serialisation ──────────────────────────────────────────────────
nlohmann::json Component::to_cyclonedx() const {
    nlohmann::json j;
    j["type"]    = type.empty() ? "library" : type;
    j["name"]    = name;
    j["version"] = version;
    if (!purl.empty())        j["purl"]        = purl;
    if (!license_id.empty())  j["licenses"]    = nlohmann::json::array({ {{"license", {{"id", license_id}}}} });
    if (!description.empty()) j["description"] = description;
    if (!hash_sha256.empty()) j["hashes"]      = nlohmann::json::array({ {{"alg","SHA-256"},{"content",hash_sha256}} });
    j["scope"] = is_direct ? "required" : "optional";
    return j;
}

nlohmann::json Component::to_spdx() const {
    return {
        {"SPDXID",           "SPDXRef-" + name + "-" + version},
        {"name",             name},
        {"versionInfo",      version},
        {"packageVersion",   version},
        {"externalRefs",     nlohmann::json::array({ {{"referenceCategory","PACKAGE-MANAGER"},{"referenceType","purl"},{"referenceLocator",purl}} })},
        {"licenseConcluded", license_id.empty() ? "NOASSERTION" : license_id},
        {"filesAnalyzed",    false},
    };
}

// ─── SbomDocument ─────────────────────────────────────────────────────────────
nlohmann::json SbomDocument::to_cyclonedx_json() const {
    nlohmann::json doc;
    doc["bomFormat"]   = "CycloneDX";
    doc["specVersion"] = "1.5";
    doc["serialNumber"] = serial_number;
    doc["version"]     = 1;
    doc["metadata"] = {
        {"timestamp", timestamp},
        {"tools", nlohmann::json::array({
            {{"vendor", tool_vendor}, {"name", "Aegis Prime SBOM Engine"}, {"version", tool_version}}
        })},
        {"component", {{"type","application"}, {"name",project_name}, {"version",project_version}}}
    };

    auto comps = nlohmann::json::array();
    for (const auto& c : components) comps.push_back(c.to_cyclonedx());
    doc["components"] = comps;

    if (!vulnerabilities.empty()) {
        auto vulns = nlohmann::json::array();
        for (const auto& v : vulnerabilities) {
            vulns.push_back({
                {"id",          v.cve_id},
                {"source",      {{"name","NVD"},{"url","https://nvd.nist.gov/vuln/detail/"+v.cve_id}}},
                {"ratings",     nlohmann::json::array({ {{"score",std::stof(v.cvss_score.empty()?"0":v.cvss_score)},{"severity",v.severity}} })},
                {"description", v.description},
                {"affects",     nlohmann::json::array({ {{"ref",v.component_name+"-"+v.component_version}} })}
            });
        }
        doc["vulnerabilities"] = vulns;
    }

    // Append cryptographic signature as metadata
    doc["_aegis"] = {{"signature", merkle_signature}, {"tool","Aegis Prime (Pty) Ltd"}};
    return doc;
}

bool SbomDocument::has_critical_findings() const {
    for (const auto& v : vulnerabilities)
        if (v.severity == "CRITICAL" || v.severity == "HIGH") return true;
    return false;
}
int SbomDocument::critical_count() const {
    int n = 0;
    for (const auto& v : vulnerabilities) if (v.severity == "CRITICAL") n++;
    return n;
}
int SbomDocument::high_count() const {
    int n = 0;
    for (const auto& v : vulnerabilities) if (v.severity == "HIGH") n++;
    return n;
}

std::string SbomDocument::to_audit_report() const {
    std::ostringstream r;
    r << "═══════════════════════════════════════════════════════════════════\n";
    r << "  AEGIS PRIME — SBOM AUDIT REPORT\n";
    r << "  Aegis Prime (Pty) Ltd | aegisprime.io\n";
    r << "═══════════════════════════════════════════════════════════════════\n\n";
    r << "Project       : " << project_name << " v" << project_version << "\n";
    r << "Scan Time     : " << timestamp << "\n";
    r << "Serial Number : " << serial_number << "\n";
    r << "Signature     : " << merkle_signature.substr(0, 32) << "...\n\n";
    r << "COMPONENTS FOUND: " << components.size() << "\n";
    r << "───────────────────────────────────────────────────────────────────\n";
    for (const auto& c : components) {
        r << "  [" << (c.is_direct ? "DIRECT" : "transitive") << "] "
          << c.name << " @ " << c.version;
        if (!c.license_id.empty()) r << " (" << c.license_id << ")";
        r << "\n";
    }
    r << "\nVULNERABILITIES FOUND: " << vulnerabilities.size()
      << " (" << critical_count() << " CRITICAL, " << high_count() << " HIGH)\n";
    r << "───────────────────────────────────────────────────────────────────\n";
    for (const auto& v : vulnerabilities) {
        r << "  [" << v.severity << "] " << v.cve_id
          << " in " << v.component_name << "@" << v.component_version
          << " | CVSS: " << v.cvss_score;
        if (!v.fix_version.empty()) r << " | FIX: upgrade to " << v.fix_version;
        r << "\n  → " << v.description.substr(0, 120) << "...\n\n";
    }
    r << "═══════════════════════════════════════════════════════════════════\n";
    r << "  This report was cryptographically signed by Aegis Prime.\n";
    r << "  Verify: aegisprime.io/verify?sn=" << serial_number << "\n";
    r << "═══════════════════════════════════════════════════════════════════\n";
    return r.str();
}

// ─── SbomGenerator constructor ────────────────────────────────────────────────
SbomGenerator::SbomGenerator(const std::string& signing_key)
    : signing_key_(signing_key) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

void SbomGenerator::log(const std::string& msg) {
    if (progress_) progress_(msg);
}

std::string SbomGenerator::get_iso8601_now() {
    auto now = std::chrono::system_clock::now();
    auto t   = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

std::string SbomGenerator::generate_uuid() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;
    std::ostringstream oss;
    auto r1 = dis(gen), r2 = dis(gen);
    oss << std::hex << std::setfill('0')
        << std::setw(8) << (r1 >> 32) << "-"
        << std::setw(4) << ((r1 >> 16) & 0xFFFF) << "-"
        << std::setw(4) << (0x4000 | (r1 & 0x0FFF)) << "-"
        << std::setw(4) << (0x8000 | ((r2 >> 48) & 0x3FFF)) << "-"
        << std::setw(12) << (r2 & 0xFFFFFFFFFFFF);
    return "urn:uuid:" + oss.str();
}

std::string SbomGenerator::build_purl(const std::string& ecosystem,
                                       const std::string& name,
                                       const std::string& version) {
    return "pkg:" + ecosystem + "/" + name + "@" + version;
}

std::string SbomGenerator::sign_document(const std::string& payload) {
    if (signing_key_.empty()) return "UNSIGNED";
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int  result_len = 0;
    HMAC(EVP_sha256(),
         signing_key_.c_str(), signing_key_.size(),
         (const unsigned char*)payload.c_str(), payload.size(),
         result, &result_len);
    std::ostringstream hex;
    for (unsigned int i = 0; i < result_len; ++i)
        hex << std::hex << std::setw(2) << std::setfill('0') << (int)result[i];
    return hex.str();
}

// ─── NPM extractor (reads package-lock.json) ─────────────────────────────────
void SbomGenerator::extract_npm(const std::filesystem::path& root,
                                  std::vector<Component>& out) {
    log("  [npm] Reading package-lock.json...");
    std::filesystem::path lockfile = root / "package-lock.json";
    if (!std::filesystem::exists(lockfile)) {
        // Fall back to package.json
        lockfile = root / "package.json";
        if (!std::filesystem::exists(lockfile)) return;
    }

    std::ifstream f(lockfile);
    try {
        auto j = nlohmann::json::parse(f);

        // package-lock.json v2/v3 has "packages" key
        if (j.contains("packages")) {
            for (auto& [pkg_path, pkg_data] : j["packages"].items()) {
                if (pkg_path.empty()) continue; // skip root
                // pkg_path is like "node_modules/lodash"
                std::string name = pkg_path;
                auto pos = name.find("node_modules/");
                if (pos != std::string::npos) name = name.substr(pos + 13);

                Component c;
                c.ecosystem  = "npm";
                c.name       = name;
                c.version    = pkg_data.value("version", "unknown");
                c.purl       = build_purl("npm", name, c.version);
                c.license_id = pkg_data.value("license", "");
                c.is_direct  = !pkg_data.value("dev", false);
                c.type       = "library";
                out.push_back(c);
            }
        } else if (j.contains("dependencies")) {
            // Older package.json style
            for (auto& [name, version_val] : j["dependencies"].items()) {
                Component c;
                c.ecosystem = "npm";
                c.name      = name;
                c.version   = version_val.is_string() ? version_val.get<std::string>() : "unknown";
                // Remove ^ ~ prefixes
                if (!c.version.empty() && (c.version[0] == '^' || c.version[0] == '~'))
                    c.version = c.version.substr(1);
                c.purl      = build_purl("npm", name, c.version);
                c.is_direct = true;
                c.type      = "library";
                out.push_back(c);
            }
        }
        log("  [npm] Found " + std::to_string(out.size()) + " packages");
    } catch (...) {
        log("  [npm] Warning: Could not parse lock file");
    }
}

// ─── PIP extractor (reads requirements.txt) ───────────────────────────────────
void SbomGenerator::extract_pip(const std::filesystem::path& root,
                                  std::vector<Component>& out) {
    log("  [pip] Reading requirements.txt...");
    std::ifstream f(root / "requirements.txt");
    if (!f.is_open()) return;
    std::string line;
    std::regex  req_re(R"(^([A-Za-z0-9_\-\.]+)[>=<!\s]*([0-9][^\s#;]*)?)");
    size_t start = out.size();
    while (std::getline(f, line)) {
        // Skip comments and empty lines
        if (line.empty() || line[0] == '#' || line[0] == '-') continue;
        std::smatch m;
        if (std::regex_search(line, m, req_re)) {
            Component c;
            c.ecosystem = "pypi";
            c.name      = m[1].str();
            c.version   = m.size() > 2 ? m[2].str() : "any";
            c.purl      = build_purl("pypi", c.name, c.version);
            c.is_direct = true;
            c.type      = "library";
            out.push_back(c);
        }
    }
    log("  [pip] Found " + std::to_string(out.size() - start) + " packages");
}

// ─── Maven extractor (reads pom.xml) ─────────────────────────────────────────
void SbomGenerator::extract_maven(const std::filesystem::path& root,
                                    std::vector<Component>& out) {
    log("  [maven] Scanning pom.xml...");
    std::ifstream f(root / "pom.xml");
    if (!f.is_open()) return;
    std::string content((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
    std::regex  dep_re(R"(<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>)");
    auto begin = std::sregex_iterator(content.begin(), content.end(), dep_re);
    auto end   = std::sregex_iterator();
    size_t start = out.size();
    for (auto it = begin; it != end; ++it) {
        auto& m = *it;
        Component c;
        c.ecosystem = "maven";
        c.name      = m[1].str() + ":" + m[2].str();
        c.version   = m[3].str();
        c.purl      = build_purl("maven", m[1].str() + "/" + m[2].str(), c.version);
        c.is_direct = true;
        c.type      = "library";
        out.push_back(c);
    }
    log("  [maven] Found " + std::to_string(out.size() - start) + " dependencies");
}

// ─── Go modules extractor ─────────────────────────────────────────────────────
void SbomGenerator::extract_go_mod(const std::filesystem::path& root,
                                     std::vector<Component>& out) {
    log("  [go] Reading go.mod...");
    std::ifstream f(root / "go.mod");
    if (!f.is_open()) return;
    std::string line;
    std::regex  req_re(R"(^\s+([^\s]+)\s+v([^\s]+))");
    bool in_require = false;
    size_t start = out.size();
    while (std::getline(f, line)) {
        if (line.find("require (") != std::string::npos) { in_require = true; continue; }
        if (in_require && line.find(")") != std::string::npos) { in_require = false; continue; }
        if (!in_require) continue;
        std::smatch m;
        if (std::regex_search(line, m, req_re)) {
            Component c;
            c.ecosystem = "golang";
            c.name      = m[1].str();
            c.version   = m[2].str();
            c.purl      = build_purl("golang", c.name, c.version);
            c.is_direct = true;
            c.type      = "library";
            out.push_back(c);
        }
    }
    log("  [go] Found " + std::to_string(out.size() - start) + " modules");
}

// ─── CVE check via OSV.dev (free public API, no key needed) ──────────────────
std::vector<VulnerabilityFinding> SbomGenerator::check_osv(const Component& comp) {
    std::vector<VulnerabilityFinding> findings;
    // OSV batch query format
    nlohmann::json query = {
        {"package", {
            {"name",      comp.name},
            {"ecosystem", comp.ecosystem == "npm"   ? "npm"   :
                          comp.ecosystem == "pypi"  ? "PyPI"  :
                          comp.ecosystem == "maven" ? "Maven" :
                          comp.ecosystem == "golang"? "Go"    : "npm"},
        }},
        {"version", comp.version}
    };

    std::string resp = http_post_json("https://api.osv.dev/v1/query", query.dump());
    if (resp.empty()) return findings;

    try {
        auto j = nlohmann::json::parse(resp);
        if (!j.contains("vulns")) return findings;
        for (const auto& vuln : j["vulns"]) {
            VulnerabilityFinding f;
            f.component_name    = comp.name;
            f.component_version = comp.version;
            f.cve_id            = vuln.value("id", "UNKNOWN");
            f.description       = vuln.value("summary", "");
            
            // Extract severity from CVSS if available
            if (vuln.contains("severity") && !vuln["severity"].empty()) {
                auto& sev = vuln["severity"][0];
                f.cvss_score = sev.value("score", "0.0");
                double score = std::stod(f.cvss_score.empty() ? "0" : f.cvss_score);
                f.severity = score >= 9.0 ? "CRITICAL" :
                             score >= 7.0 ? "HIGH"     :
                             score >= 4.0 ? "MEDIUM"   : "LOW";
            } else {
                f.severity   = "MEDIUM";
                f.cvss_score = "N/A";
            }
            findings.push_back(f);
        }
    } catch (...) {}
    return findings;
}

// ─── Main scan function ───────────────────────────────────────────────────────
SbomDocument SbomGenerator::scan(const std::filesystem::path& project_root,
                                   const std::string& project_name,
                                   const std::string& project_version) {
    log("Aegis Prime SBOM Engine v1.0 — starting scan");
    log("Target: " + project_root.string());

    SbomDocument doc;
    doc.serial_number   = generate_uuid();
    doc.timestamp       = get_iso8601_now();
    doc.project_name    = project_name.empty() ? project_root.filename().string() : project_name;
    doc.project_version = project_version.empty() ? "unknown" : project_version;
    doc.tool_vendor     = "Aegis Prime (Pty) Ltd";
    doc.tool_version    = "1.0.0";

    // Detect and extract from each package manager present
    if (std::filesystem::exists(project_root / "package-lock.json") ||
        std::filesystem::exists(project_root / "package.json"))
        extract_npm(project_root, doc.components);

    if (std::filesystem::exists(project_root / "requirements.txt"))
        extract_pip(project_root, doc.components);

    if (std::filesystem::exists(project_root / "pom.xml"))
        extract_maven(project_root, doc.components);

    if (std::filesystem::exists(project_root / "go.mod"))
        extract_go_mod(project_root, doc.components);

    log("Total components found: " + std::to_string(doc.components.size()));

    // CVE scanning
    if (cve_scanning_ && !doc.components.empty()) {
        log("Running CVE checks via OSV.dev...");
        for (const auto& comp : doc.components) {
            auto vulns = check_osv(comp);
            for (auto& v : vulns) doc.vulnerabilities.push_back(v);
        }
        log("CVE check complete. Findings: " + std::to_string(doc.vulnerabilities.size()));
    }

    // Sign the document
    doc.merkle_signature = sign_document(doc.to_cyclonedx_json().dump());
    log("Document signed: " + doc.merkle_signature.substr(0, 16) + "...");

    return doc;
}

} // namespace aegis::sbom
