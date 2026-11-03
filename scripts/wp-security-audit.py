#!/usr/bin/env python3
"""
WordPress Security Audit — runs via SSH on Hostinger sites.
Collects data, auto-fixes safe issues, generates JSON report.
"""
import json
import subprocess
import sys
import os
import re
from datetime import datetime, timezone

SSH_HOST = "visit-rj-hostinger"
WP_SKIP = "--skip-plugins=elementor-pro"
BACKUP_REMOTE_DIR = "~/backups"

WP_SITES = [
    "abihrj.com.br",
    "sindhoteisrj.com.br",
    "hoteisrio.com.br",
    "visit-rj.com",
    "iamagica.online",
    "hotelariaeturismo.com.br",
    "blog.agenciarmktdigital.com.br",
    "blog.criacaodesitesbr.com",
    "blog.leisedecretosrj.com.br",
]

CRITICAL_SITES = {"abihrj.com.br", "sindhoteisrj.com.br", "visit-rj.com"}


def ssh_cmd(cmd, timeout=30):
    try:
        r = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=15", "-o", "StrictHostKeyChecking=no", SSH_HOST, cmd],
            capture_output=True, text=True, timeout=timeout,
        )
        return r.stdout.strip()
    except (subprocess.TimeoutExpired, Exception) as e:
        return f"SSH_ERROR: {e}"


def wp_cmd(site, cmd):
    return ssh_cmd(f"cd ~/domains/{site}/public_html && wp {cmd} {WP_SKIP} 2>/dev/null")


def http_check(site):
    try:
        r = subprocess.run(
            ["curl", "-sL", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "15", f"https://{site}/"],
            capture_output=True, text=True, timeout=20,
        )
        return int(r.stdout.strip())
    except Exception:
        return 0


def parse_json_or_empty(text):
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []


def ssl_expiry(site):
    try:
        r = subprocess.run(
            f"echo | openssl s_client -servername {site} -connect {site}:443 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null",
            shell=True, capture_output=True, text=True, timeout=15,
        )
        match = re.search(r"notAfter=(.*)", r.stdout)
        return match.group(1).strip() if match else "unknown"
    except Exception:
        return "unknown"


def backup_site(site):
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    bkdir = f"{BACKUP_REMOTE_DIR}/{site}"
    ssh_cmd(f"mkdir -p {bkdir}")

    db_host = wp_cmd(site, "config get DB_HOST")
    db_user = wp_cmd(site, "config get DB_USER")
    db_pass = wp_cmd(site, "config get DB_PASSWORD")
    db_name = wp_cmd(site, "config get DB_NAME")

    if not db_host or "SSH_ERROR" in db_host:
        return None, "backup failed: cannot read DB credentials"

    dump = ssh_cmd(
        f"mysqldump --single-transaction --no-tablespaces -h '{db_host}' -u '{db_user}' -p'{db_pass}' '{db_name}' 2>/dev/null | gzip > '{bkdir}/db_{stamp}.sql.gz' && echo OK || echo FAIL",
        timeout=120,
    )
    if "OK" not in dump:
        return None, "backup failed: mysqldump error"

    tar = ssh_cmd(
        f"tar czf '{bkdir}/plugins_{stamp}.tar.gz' -C ~/domains/{site}/public_html/wp-content plugins 2>/dev/null && echo OK || echo FAIL",
        timeout=120,
    )
    if "OK" not in tar:
        return None, "backup failed: plugins tar error"

    ssh_cmd(f"find {bkdir} -name '*.sql.gz' -mtime +7 -delete 2>/dev/null; find {bkdir} -name '*.tar.gz' -mtime +7 -delete 2>/dev/null")
    return stamp, None


def audit_site(site):
    print(f"  Collecting data...", file=sys.stderr)
    data = {"site": site, "is_critical": site in CRITICAL_SITES}

    data["http_status"] = http_check(site)
    data["wp_version"] = wp_cmd(site, "core version").replace("\r", "").replace("\n", "")

    data["core_updates"] = parse_json_or_empty(wp_cmd(site, "core check-update --format=json"))

    checksums = wp_cmd(site, "core verify-checksums 2>&1")
    # Filter out known benign warnings (wp-config-sample.php is often modified by hosts)
    checksums_real = "\n".join(
        line for line in checksums.split("\n")
        if "wp-config-sample.php" not in line and ".rnd" not in line
    )
    data["core_integrity"] = "fail" if re.search(r"should not exist|doesn't verify", checksums_real, re.I) else "pass"

    data["plugin_list"] = parse_json_or_empty(wp_cmd(site, "plugin list --format=json"))
    data["plugin_updates"] = parse_json_or_empty(wp_cmd(site, "plugin list --update=available --format=json"))

    p_checksums = wp_cmd(site, "plugin verify-checksums --all 2>&1")
    # "Could not retrieve checksums" means plugin isn't on WP.org (custom/premium/hostinger) — not a real issue
    # Only flag actual checksum mismatches
    p_checksums_real = "\n".join(
        line for line in p_checksums.split("\n")
        if "Could not retrieve" not in line and "Couldn't fetch" not in line
    )
    data["plugin_integrity"] = "fail" if re.search(r"doesn't verify|should not exist|mismatch", p_checksums_real, re.I) else "pass"

    data["theme_updates"] = parse_json_or_empty(wp_cmd(site, "theme list --update=available --format=json"))
    data["admin_users"] = parse_json_or_empty(wp_cmd(site, "user list --role=administrator --format=json --fields=ID,user_login,user_email,user_registered"))

    suspicious_raw = ssh_cmd(
        f"find ~/domains/{site}/public_html -maxdepth 2 \\( -name '*.bak' -o -name '*.sql' -o -name '*.zip' -o -name '*.tar.gz' -o -name 'wp-config.php.bak' \\) 2>/dev/null | head -20"
    )
    data["suspicious_files"] = [f for f in suspicious_raw.split("\n") if f.strip() and "SSH_ERROR" not in f]

    # Detect real malware: PHP files injected into WP core dirs (wp-admin/wp-includes)
    # that don't belong there (files WP core verify-checksums flags as "should not exist")
    injected_raw = ssh_cmd(
        f"cd ~/domains/{site}/public_html && wp core verify-checksums 2>&1 | grep 'should not exist' | sed 's/Warning: File should not exist: //'",
        timeout=60,
    )
    data["injected_core_files"] = [f for f in injected_raw.split("\n") if f.strip() and "SSH_ERROR" not in f and f.strip().endswith(".php")]

    # Detect actual webshells/backdoors (precise patterns, not generic words)
    webshell_raw = ssh_cmd(
        f"grep -rln 'Tiny File Manager\\|FilesMan\\|WSO \\|Web Shell\\|c99shell\\|r57shell\\|b374k\\|FileSpy\\|Fake WordPress' ~/domains/{site}/public_html/wp-admin/ ~/domains/{site}/public_html/wp-includes/ 2>/dev/null | head -10"
    )
    data["webshells"] = [f for f in webshell_raw.split("\n") if f.strip() and "SSH_ERROR" not in f]

    data["nulled_plugins"] = data["injected_core_files"] + data["webshells"]

    data["wp_config_perms"] = ssh_cmd(f"stat -c '%a' ~/domains/{site}/public_html/wp-config.php 2>/dev/null").replace("'", "").strip()
    data["htaccess_perms"] = ssh_cmd(f"stat -c '%a' ~/domains/{site}/public_html/.htaccess 2>/dev/null").replace("'", "").strip()
    data["ssl_expiry"] = ssl_expiry(site)

    return data


def apply_fixes(site, data):
    fixes = []
    errors = []

    if data["http_status"] == 0:
        errors.append("Site unreachable — skipping all fixes")
        return fixes, errors

    perms = data.get("wp_config_perms", "")
    if perms and perms not in ("440", "400", "444"):
        ssh_cmd(f"chmod 440 ~/domains/{site}/public_html/wp-config.php")
        fixes.append(f"wp-config.php permissions: {perms} → 440")

    ht_perms = data.get("htaccess_perms", "")
    if ht_perms and ht_perms not in ("644", "444"):
        ssh_cmd(f"chmod 644 ~/domains/{site}/public_html/.htaccess")
        fixes.append(f".htaccess permissions: {ht_perms} → 644")

    if data.get("suspicious_files"):
        quarantine = f"{BACKUP_REMOTE_DIR}/{site}/quarantine_{datetime.now().strftime('%Y%m%d')}"
        ssh_cmd(f"mkdir -p {quarantine}")
        for fpath in data["suspicious_files"]:
            fname = os.path.basename(fpath)
            result = ssh_cmd(f"mv '{fpath}' '{quarantine}/{fname}' 2>/dev/null && echo OK || echo FAIL")
            if "OK" in result:
                fixes.append(f"Quarantined: {fname}")
            else:
                errors.append(f"Failed to quarantine: {fname}")

    # Auto-quarantine injected PHP files in WP core directories
    if data.get("injected_core_files"):
        quarantine = f"{BACKUP_REMOTE_DIR}/{site}/quarantine_malware_{datetime.now().strftime('%Y%m%d')}"
        ssh_cmd(f"mkdir -p {quarantine}")
        for fpath in data["injected_core_files"]:
            fname = os.path.basename(fpath)
            full_path = f"~/domains/{site}/public_html/{fpath}"
            result = ssh_cmd(f"mv '{full_path}' '{quarantine}/{fname}' 2>/dev/null && echo OK || echo FAIL")
            if "OK" in result:
                fixes.append(f"MALWARE REMOVED: {fpath} → quarantine")
            else:
                errors.append(f"CRITICAL: Failed to quarantine malware: {fpath}")

    if data.get("webshells"):
        quarantine = f"{BACKUP_REMOTE_DIR}/{site}/quarantine_malware_{datetime.now().strftime('%Y%m%d')}"
        ssh_cmd(f"mkdir -p {quarantine}")
        for fpath in data["webshells"]:
            fname = os.path.basename(fpath)
            result = ssh_cmd(f"mv '{fpath}' '{quarantine}/{fname}' 2>/dev/null && echo OK || echo FAIL")
            if "OK" in result:
                fixes.append(f"WEBSHELL REMOVED: {fname} → quarantine")
            else:
                errors.append(f"CRITICAL: Failed to quarantine webshell: {fpath}")

    if data["core_integrity"] == "fail" and not data.get("injected_core_files"):
        errors.append("Core integrity issue — investigate manually")

    is_critical = site in CRITICAL_SITES

    if not is_critical and data.get("plugin_updates"):
        print(f"  Backing up before plugin updates...", file=sys.stderr)
        bk_stamp, bk_err = backup_site(site)
        if bk_stamp:
            for plugin in data["plugin_updates"]:
                pname = plugin.get("name", "")
                if not pname:
                    continue
                print(f"  Updating plugin: {pname}...", file=sys.stderr)
                result = wp_cmd(site, f"plugin update {pname} 2>&1")
                if re.search(r"success|updated", result, re.I):
                    verify = http_check(site)
                    if verify == 200:
                        fixes.append(f"Plugin updated: {pname}")
                    else:
                        print(f"  ROLLBACK: {pname} (HTTP {verify})", file=sys.stderr)
                        ssh_cmd(f"cd ~/domains/{site}/public_html/wp-content && tar xzf {BACKUP_REMOTE_DIR}/{site}/plugins_{bk_stamp}.tar.gz 2>/dev/null")
                        errors.append(f"Plugin {pname} rolled back (HTTP {verify})")
                else:
                    errors.append(f"Plugin {pname} update failed")
        else:
            errors.append(f"Skipped plugin updates — {bk_err}")

    if not is_critical:
        minor_updates = [u for u in data.get("core_updates", []) if isinstance(u, dict) and u.get("update_type") == "minor"]
        if minor_updates:
            print(f"  Minor core update available...", file=sys.stderr)
            bk_stamp, bk_err = backup_site(site)
            if bk_stamp:
                result = wp_cmd(site, "core update --minor 2>&1")
                if re.search(r"success|updated", result, re.I):
                    verify = http_check(site)
                    if verify == 200:
                        fixes.append("WP core minor update applied")
                    else:
                        errors.append(f"WP core update may have issues (HTTP {verify})")
                else:
                    errors.append("WP core minor update failed")
    else:
        update_count = len(data.get("plugin_updates", []))
        if update_count > 0:
            errors.append(f"CRITICAL SITE: {update_count} plugin update(s) pending — manual approval required")

    return fixes, errors


def compute_severity(data):
    issues = 0
    if data["http_status"] != 200:
        issues += 1
    if data["core_integrity"] == "fail":
        issues += 1
    if data["plugin_integrity"] == "fail":
        issues += 1
    issues += len(data.get("suspicious_files", []))
    issues += len(data.get("nulled_plugins", []))
    issues += len(data.get("plugin_updates", []))
    issues += len(data.get("theme_updates", []))
    issues += len(data.get("core_updates", []))
    perms = data.get("wp_config_perms", "")
    if perms and perms not in ("440", "400", "444", ""):
        issues += 1

    severity = "ok"
    if issues > 0:
        severity = "warning"
    if data.get("nulled_plugins") or data["core_integrity"] == "fail":
        severity = "critical"
    if data["http_status"] != 200:
        severity = "critical"

    return issues, severity


def main():
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(script_dir, "..", "dashboard", "data")
    os.makedirs(data_dir, exist_ok=True)
    report_path = os.path.join(data_dir, f"{today}.json")

    print(f"=== WP Security Audit — {today} ===", file=sys.stderr)
    print(f"Auditing {len(WP_SITES)} sites...", file=sys.stderr)

    all_sites = []

    for site in WP_SITES:
        print(f"\n--- {site} ---", file=sys.stderr)

        data = audit_site(site)
        data["timestamp"] = timestamp

        print(f"  Applying auto-fixes...", file=sys.stderr)
        fixes, errors = apply_fixes(site, data)
        data["fixes_applied"] = fixes
        data["fix_errors"] = errors

        issues, severity = compute_severity(data)
        data["total_issues"] = issues
        data["severity"] = severity
        data["total_fixes"] = len(fixes)

        all_sites.append(data)

        status_label = severity.upper()
        print(f"  Status: {status_label} — {issues} issues, {len(fixes)} fixes applied", file=sys.stderr)

    ok = sum(1 for s in all_sites if s["severity"] == "ok")
    warning = sum(1 for s in all_sites if s["severity"] == "warning")
    critical = sum(1 for s in all_sites if s["severity"] == "critical")
    total_issues = sum(s["total_issues"] for s in all_sites)
    total_fixes = sum(s["total_fixes"] for s in all_sites)
    overall = "critical" if critical > 0 else ("warning" if warning > 0 else "ok")

    report = {
        "date": today,
        "timestamp": timestamp,
        "summary": {
            "total_sites": len(all_sites),
            "ok": ok,
            "warning": warning,
            "critical": critical,
            "total_issues": total_issues,
            "total_fixes": total_fixes,
            "overall_status": overall,
        },
        "sites": all_sites,
    }

    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"\nReport saved: {report_path}", file=sys.stderr)
    print(report_path)


if __name__ == "__main__":
    main()
