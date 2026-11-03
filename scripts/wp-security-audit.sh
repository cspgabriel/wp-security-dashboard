#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DATA_DIR="$REPO_DIR/dashboard/data"
TODAY=$(date +%Y-%m-%d)
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
REPORT_JSON="$DATA_DIR/${TODAY}.json"
SSH_HOST="visit-rj-hostinger"
BACKUP_REMOTE_DIR="~/backups"
WP_SKIP="--skip-plugins=elementor-pro"

WP_SITES=(
  "abihrj.com.br"
  "sindhoteisrj.com.br"
  "hoteisrio.com.br"
  "visit-rj.com"
  "iamagica.online"
  "hotelariaeturismo.com.br"
  "blog.agenciarmktdigital.com.br"
  "blog.criacaodesitesbr.com"
  "blog.leisedecretosrj.com.br"
)

CRITICAL_SITES=("abihrj.com.br" "sindhoteisrj.com.br" "visit-rj.com")

mkdir -p "$DATA_DIR"

is_critical() {
  local site="$1"
  for cs in "${CRITICAL_SITES[@]}"; do
    [[ "$cs" == "$site" ]] && return 0
  done
  return 1
}

ssh_cmd() {
  ssh -o ConnectTimeout=15 -o StrictHostKeyChecking=no "$SSH_HOST" "$1" 2>/dev/null || echo "SSH_ERROR"
}

wp_cmd() {
  local site="$1" cmd="$2"
  ssh_cmd "cd ~/domains/${site}/public_html && wp ${cmd} ${WP_SKIP} 2>/dev/null"
}

backup_site() {
  local site="$1"
  local stamp
  stamp=$(date +%Y%m%d_%H%M%S)
  local bkdir="${BACKUP_REMOTE_DIR}/${site}"

  ssh_cmd "mkdir -p ${bkdir}"

  local db_host db_user db_pass db_name
  db_host=$(wp_cmd "$site" "config get DB_HOST")
  db_user=$(wp_cmd "$site" "config get DB_USER")
  db_pass=$(wp_cmd "$site" "config get DB_PASSWORD")
  db_name=$(wp_cmd "$site" "config get DB_NAME")

  if [[ -z "$db_host" || "$db_host" == "SSH_ERROR" ]]; then
    echo "BACKUP_FAIL:db_creds"
    return 1
  fi

  local dump_result
  dump_result=$(ssh_cmd "mysqldump --single-transaction --no-tablespaces -h '${db_host}' -u '${db_user}' -p'${db_pass}' '${db_name}' 2>/dev/null | gzip > '${bkdir}/db_${stamp}.sql.gz' && echo OK || echo FAIL")

  if [[ "$dump_result" != *"OK"* ]]; then
    echo "BACKUP_FAIL:db_dump"
    return 1
  fi

  ssh_cmd "tar czf '${bkdir}/plugins_${stamp}.tar.gz' -C ~/domains/${site}/public_html/wp-content plugins 2>/dev/null && echo OK || echo FAIL" | grep -q OK || {
    echo "BACKUP_FAIL:plugins_tar"
    return 1
  }

  ssh_cmd "find ${bkdir} -name '*.sql.gz' -mtime +7 -delete 2>/dev/null; find ${bkdir} -name '*.tar.gz' -mtime +7 -delete 2>/dev/null"

  echo "BACKUP_OK:${stamp}"
}

audit_site() {
  local site="$1"
  local result="{}"

  local http_status
  http_status=$(curl -sL -o /dev/null -w '%{http_code}' --max-time 15 "https://${site}/" 2>/dev/null || echo "000")

  local wp_version
  wp_version=$(wp_cmd "$site" "core version" | tr -d '\r\n')

  local core_check
  core_check=$(wp_cmd "$site" "core check-update --format=json" | tr -d '\r\n')

  local core_checksums
  core_checksums=$(wp_cmd "$site" "core verify-checksums 2>&1" | tr -d '\r\n')
  local core_integrity="pass"
  if echo "$core_checksums" | grep -qi "warning\|error\|mismatch"; then
    core_integrity="fail"
  fi

  local plugin_list
  plugin_list=$(wp_cmd "$site" "plugin list --format=json")

  local plugin_checksums
  plugin_checksums=$(wp_cmd "$site" "plugin verify-checksums --all 2>&1")
  local plugin_integrity="pass"
  if echo "$plugin_checksums" | grep -qi "warning\|error\|could not"; then
    plugin_integrity="fail"
  fi

  local plugin_updates
  plugin_updates=$(wp_cmd "$site" "plugin list --update=available --format=json")

  local theme_updates
  theme_updates=$(wp_cmd "$site" "theme list --update=available --format=json")

  local user_list
  user_list=$(wp_cmd "$site" "user list --role=administrator --format=json --fields=ID,user_login,user_email,user_registered")

  local suspicious_files
  suspicious_files=$(ssh_cmd "find ~/domains/${site}/public_html -maxdepth 2 -name '*.bak' -o -name '*.sql' -o -name '*.zip' -o -name '*.tar.gz' -o -name 'wp-config.php.bak' 2>/dev/null | head -20")

  local nulled_check
  nulled_check=$(ssh_cmd "grep -rl 'nulled\|GPL Starter\|activator\|wso shell\|c99shell\|r57shell\|b374k' ~/domains/${site}/public_html/wp-content/plugins/ 2>/dev/null | head -10" || true)

  local file_perms
  file_perms=$(ssh_cmd "stat -c '%a' ~/domains/${site}/public_html/wp-config.php 2>/dev/null" | tr -d '\r\n')

  local htaccess_perms
  htaccess_perms=$(ssh_cmd "stat -c '%a' ~/domains/${site}/public_html/.htaccess 2>/dev/null" | tr -d '\r\n')

  local ssl_expiry
  ssl_expiry=$(echo | openssl s_client -servername "$site" -connect "${site}:443" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | sed 's/notAfter=//' || echo "unknown")

  cat <<ENDJSON
{
  "site": "${site}",
  "timestamp": "${TIMESTAMP}",
  "http_status": ${http_status},
  "wp_version": "${wp_version}",
  "core_updates": ${core_check:-"[]"},
  "core_integrity": "${core_integrity}",
  "plugin_list": ${plugin_list:-"[]"},
  "plugin_updates": ${plugin_updates:-"[]"},
  "plugin_integrity": "${plugin_integrity}",
  "theme_updates": ${theme_updates:-"[]"},
  "admin_users": ${user_list:-"[]"},
  "suspicious_files": $(echo "$suspicious_files" | python3 -I -c "import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip() and l.strip()!='SSH_ERROR']))" 2>/dev/null || echo '[]'),
  "nulled_plugins": $(echo "$nulled_check" | python3 -I -c "import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip() and l.strip()!='SSH_ERROR']))" 2>/dev/null || echo '[]'),
  "wp_config_perms": "${file_perms}",
  "htaccess_perms": "${htaccess_perms}",
  "ssl_expiry": "${ssl_expiry}",
  "is_critical": $(is_critical "$site" && echo "true" || echo "false"),
  "fixes_applied": [],
  "fix_errors": []
}
ENDJSON
}

apply_fixes() {
  local site="$1"
  local audit_json="$2"
  local fixes=()
  local errors=()

  local http_status
  http_status=$(echo "$audit_json" | python3 -I -c "import sys,json; print(json.load(sys.stdin)['http_status'])")

  if [[ "$http_status" == "000" ]]; then
    errors+=("Site unreachable — skipping all fixes")
    echo "{\"fixes\": $(python3 -I -c "import json; print(json.dumps($(printf '%s\n' "${fixes[@]+"${fixes[@]}"}" | python3 -I -c "import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))" 2>/dev/null || echo '[]'))"), \"errors\": $(python3 -I -c "import json; print(json.dumps($(printf '%s\n' "${errors[@]+"${errors[@]}"}" | python3 -I -c "import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))" 2>/dev/null || echo '[]'))") }"
    return
  fi

  local wp_config_perms
  wp_config_perms=$(echo "$audit_json" | python3 -I -c "import sys,json; print(json.load(sys.stdin).get('wp_config_perms',''))")
  if [[ -n "$wp_config_perms" && "$wp_config_perms" != "440" && "$wp_config_perms" != "400" && "$wp_config_perms" != "444" ]]; then
    ssh_cmd "chmod 440 ~/domains/${site}/public_html/wp-config.php"
    fixes+=("wp-config.php permissions fixed: ${wp_config_perms} → 440")
  fi

  local htaccess_perms
  htaccess_perms=$(echo "$audit_json" | python3 -I -c "import sys,json; print(json.load(sys.stdin).get('htaccess_perms',''))")
  if [[ -n "$htaccess_perms" && "$htaccess_perms" != "644" && "$htaccess_perms" != "444" ]]; then
    ssh_cmd "chmod 644 ~/domains/${site}/public_html/.htaccess"
    fixes+=(".htaccess permissions fixed: ${htaccess_perms} → 644")
  fi

  local suspicious_count
  suspicious_count=$(echo "$audit_json" | python3 -I -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('suspicious_files',[])))")
  if [[ "$suspicious_count" -gt 0 ]]; then
    local quarantine_dir="${BACKUP_REMOTE_DIR}/${site}/quarantine_$(date +%Y%m%d)"
    ssh_cmd "mkdir -p ${quarantine_dir}"
    local files_list
    files_list=$(echo "$audit_json" | python3 -I -c "import sys,json; [print(f) for f in json.load(sys.stdin).get('suspicious_files',[])]")
    while IFS= read -r fpath; do
      [[ -z "$fpath" ]] && continue
      local fname
      fname=$(basename "$fpath")
      ssh_cmd "mv '${fpath}' '${quarantine_dir}/${fname}' 2>/dev/null && echo OK || echo FAIL" | grep -q OK && \
        fixes+=("Quarantined suspicious file: ${fname}") || \
        errors+=("Failed to quarantine: ${fname}")
    done <<< "$files_list"
  fi

  local nulled_count
  nulled_count=$(echo "$audit_json" | python3 -I -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('nulled_plugins',[])))")
  if [[ "$nulled_count" -gt 0 ]]; then
    errors+=("CRITICAL: ${nulled_count} nulled/malicious file(s) detected — requires manual review")
  fi

  if ! is_critical "$site"; then
    local update_count
    update_count=$(echo "$audit_json" | python3 -I -c "import sys,json; print(len(json.load(sys.stdin).get('plugin_updates',[])))")
    if [[ "$update_count" -gt 0 ]]; then
      echo "  Backing up before plugin updates..." >&2
      local bk_result
      bk_result=$(backup_site "$site")
      if [[ "$bk_result" == BACKUP_OK* ]]; then
        local plugins_to_update
        plugins_to_update=$(echo "$audit_json" | python3 -I -c "import sys,json; [print(p['name']) for p in json.load(sys.stdin).get('plugin_updates',[])]")
        while IFS= read -r plugin_name; do
          [[ -z "$plugin_name" ]] && continue
          echo "  Updating plugin: ${plugin_name}..." >&2
          local update_result
          update_result=$(wp_cmd "$site" "plugin update ${plugin_name} 2>&1")
          if echo "$update_result" | grep -qi "success\|updated"; then
            local verify
            verify=$(curl -sL -o /dev/null -w '%{http_code}' --max-time 15 "https://${site}/" 2>/dev/null || echo "000")
            if [[ "$verify" == "200" ]]; then
              fixes+=("Plugin updated: ${plugin_name}")
            else
              echo "  ROLLBACK: ${plugin_name} broke site (HTTP ${verify})" >&2
              local bk_stamp="${bk_result#BACKUP_OK:}"
              ssh_cmd "cd ~/domains/${site}/public_html/wp-content && tar xzf ${BACKUP_REMOTE_DIR}/${site}/plugins_${bk_stamp}.tar.gz 2>/dev/null"
              errors+=("Plugin ${plugin_name} update rolled back — site returned HTTP ${verify}")
            fi
          else
            errors+=("Plugin ${plugin_name} update failed")
          fi
        done <<< "$plugins_to_update"
      else
        errors+=("Skipped plugin updates — backup failed: ${bk_result}")
      fi
    fi

    local core_update_available
    core_update_available=$(echo "$audit_json" | python3 -I -c "
import sys,json
updates = json.load(sys.stdin).get('core_updates',[])
minor = [u for u in updates if u.get('update_type') == 'minor']
print('yes' if minor else 'no')
" 2>/dev/null || echo "no")

    if [[ "$core_update_available" == "yes" ]]; then
      echo "  Minor core update available — applying..." >&2
      local bk_result
      bk_result=$(backup_site "$site")
      if [[ "$bk_result" == BACKUP_OK* ]]; then
        local core_result
        core_result=$(wp_cmd "$site" "core update --minor 2>&1")
        if echo "$core_result" | grep -qi "success\|updated"; then
          local verify
          verify=$(curl -sL -o /dev/null -w '%{http_code}' --max-time 15 "https://${site}/" 2>/dev/null || echo "000")
          if [[ "$verify" == "200" ]]; then
            fixes+=("WP core minor update applied")
          else
            errors+=("WP core update may have caused issues (HTTP ${verify}) — check manually")
          fi
        else
          errors+=("WP core minor update failed")
        fi
      fi
    fi
  else
    local security_updates
    security_updates=$(echo "$audit_json" | python3 -I -c "
import sys,json
updates = json.load(sys.stdin).get('plugin_updates',[])
# For critical sites, only report — don't auto-update
print(len(updates))
" 2>/dev/null || echo "0")
    if [[ "$security_updates" -gt 0 ]]; then
      errors+=("CRITICAL SITE: ${security_updates} plugin update(s) pending — manual approval required")
    fi
  fi

  local core_integrity
  core_integrity=$(echo "$audit_json" | python3 -I -c "import sys,json; print(json.load(sys.stdin).get('core_integrity','pass'))")
  if [[ "$core_integrity" == "fail" ]]; then
    errors+=("Core integrity check FAILED — possible file tampering, requires investigation")
  fi

  python3 -I -c "
import json, sys
fixes = []
errors = []
for line in '''$(printf '%s\n' "${fixes[@]+"${fixes[@]}"}")'''.strip().split('\n'):
    if line.strip(): fixes.append(line.strip())
for line in '''$(printf '%s\n' "${errors[@]+"${errors[@]}"}")'''.strip().split('\n'):
    if line.strip(): errors.append(line.strip())
print(json.dumps({'fixes': fixes, 'errors': errors}))
"
}

echo "=== WP Security Audit — ${TODAY} ===" >&2
echo "Auditing ${#WP_SITES[@]} sites..." >&2

ALL_RESULTS="[]"

for site in "${WP_SITES[@]}"; do
  echo "" >&2
  echo "--- ${site} ---" >&2

  echo "  Collecting audit data..." >&2
  site_audit=$(audit_site "$site")

  echo "  Applying auto-fixes..." >&2
  fix_result=$(echo "$site_audit" | apply_fixes "$site")

  merged=$(python3 -I -c "
import json, sys
audit = json.loads('''${site_audit}''')
fixes = json.loads('''${fix_result}''')
audit['fixes_applied'] = fixes.get('fixes', [])
audit['fix_errors'] = fixes.get('errors', [])

total_issues = 0
if audit['http_status'] != 200: total_issues += 1
if audit['core_integrity'] == 'fail': total_issues += 1
if audit['plugin_integrity'] == 'fail': total_issues += 1
total_issues += len(audit.get('suspicious_files', []))
total_issues += len(audit.get('nulled_plugins', []))
total_issues += len(audit.get('plugin_updates', []))
total_issues += len(audit.get('theme_updates', []))
total_issues += len(audit.get('core_updates', []))
if audit.get('wp_config_perms','') not in ('440','400','444',''): total_issues += 1

severity = 'ok'
if total_issues > 0: severity = 'warning'
if len(audit.get('nulled_plugins',[])) > 0 or audit['core_integrity'] == 'fail': severity = 'critical'
if audit['http_status'] != 200: severity = 'critical'

audit['total_issues'] = total_issues
audit['severity'] = severity
audit['total_fixes'] = len(fixes.get('fixes', []))

print(json.dumps(audit))
")

  ALL_RESULTS=$(python3 -I -c "
import json
results = json.loads('''${ALL_RESULTS}''')
new_item = json.loads('''${merged}''')
results.append(new_item)
print(json.dumps(results))
")

  echo "  Status: $(echo "$merged" | python3 -I -c "import sys,json; d=json.load(sys.stdin); print(f\"{d['severity'].upper()} — {d['total_issues']} issues, {d['total_fixes']} fixes applied\")")" >&2
done

SUMMARY=$(python3 -I -c "
import json
results = json.loads('''${ALL_RESULTS}''')
total_sites = len(results)
ok = sum(1 for r in results if r['severity'] == 'ok')
warning = sum(1 for r in results if r['severity'] == 'warning')
critical = sum(1 for r in results if r['severity'] == 'critical')
total_issues = sum(r['total_issues'] for r in results)
total_fixes = sum(r['total_fixes'] for r in results)
overall = 'critical' if critical > 0 else ('warning' if warning > 0 else 'ok')

report = {
    'date': '${TODAY}',
    'timestamp': '${TIMESTAMP}',
    'summary': {
        'total_sites': total_sites,
        'ok': ok,
        'warning': warning,
        'critical': critical,
        'total_issues': total_issues,
        'total_fixes': total_fixes,
        'overall_status': overall
    },
    'sites': results
}
print(json.dumps(report, indent=2, ensure_ascii=False))
")

echo "$SUMMARY" > "$REPORT_JSON"
echo "" >&2
echo "Report saved to ${REPORT_JSON}" >&2
echo "$REPORT_JSON"
