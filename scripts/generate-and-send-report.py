#!/usr/bin/env python3
"""
Generates a visual HTML email report from the daily audit JSON
and sends it via Brevo (Sendinblue) API.
Also updates the dashboard index.
"""
import json
import os
import sys
import glob
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

BREVO_API_KEY = os.environ.get("BREVO_API_KEY", "")
BREVO_FROM_EMAIL = os.environ.get("BREVO_FROM_EMAIL", "contato@agenciarmktdigital.com.br")
BREVO_FROM_NAME = os.environ.get("BREVO_FROM_NAME", "AgenciAR Digital")
TO_EMAILS = [
    {"email": "marketing@hoteisrio.com.br", "name": "Marketing HoteisRIO"},
    {"email": "cspgabriel@outlook.com.br", "name": "Gabriel Salles"},
]
DASHBOARD_URL = "https://cspgabriel.github.io/wp-security-dashboard/"


def severity_color(sev):
    return {"ok": "#10b981", "warning": "#f59e0b", "critical": "#ef4444"}.get(sev, "#6b7280")


def severity_icon(sev):
    return {"ok": "&#10003;", "warning": "&#9888;", "critical": "&#10007;"}.get(sev, "?")


def severity_label(sev):
    return {"ok": "Seguro", "warning": "Atenção", "critical": "Crítico"}.get(sev, "Desconhecido")


def generate_html(report):
    s = report["summary"]
    date_fmt = datetime.fromisoformat(report["timestamp"].replace("Z", "+00:00")).strftime("%d/%m/%Y %H:%M UTC")
    overall_color = severity_color(s["overall_status"])
    overall_label = severity_label(s["overall_status"])

    sites_html = ""
    for site in report["sites"]:
        sc = severity_color(site["severity"])
        si = severity_icon(site["severity"])
        sl = severity_label(site["severity"])

        plugin_updates = site.get("plugin_updates", [])
        plugin_rows = ""
        for p in plugin_updates[:10]:
            plugin_rows += f"""<tr>
                <td style="padding:6px 12px;border-bottom:1px solid #e5e7eb;font-size:13px;">{p.get('name','?')}</td>
                <td style="padding:6px 12px;border-bottom:1px solid #e5e7eb;font-size:13px;">{p.get('version','?')}</td>
                <td style="padding:6px 12px;border-bottom:1px solid #e5e7eb;font-size:13px;">{p.get('update_version','?')}</td>
            </tr>"""

        fixes_html = ""
        if site.get("fixes_applied"):
            fixes_items = "".join(f'<li style="color:#10b981;font-size:13px;margin:2px 0;">{f}</li>' for f in site["fixes_applied"])
            fixes_html = f'<div style="margin-top:8px;"><strong style="color:#10b981;">Correções aplicadas:</strong><ul style="margin:4px 0;padding-left:20px;">{fixes_items}</ul></div>'

        errors_html = ""
        if site.get("fix_errors"):
            err_items = "".join(f'<li style="color:#ef4444;font-size:13px;margin:2px 0;">{e}</li>' for e in site["fix_errors"])
            errors_html = f'<div style="margin-top:8px;"><strong style="color:#ef4444;">Alertas / pendências:</strong><ul style="margin:4px 0;padding-left:20px;">{err_items}</ul></div>'

        suspicious_html = ""
        if site.get("suspicious_files"):
            sf_items = "".join(f'<li style="font-size:12px;color:#92400e;">{f}</li>' for f in site["suspicious_files"][:5])
            suspicious_html = f'<div style="margin-top:8px;background:#fef3c7;padding:8px;border-radius:6px;"><strong>Arquivos suspeitos:</strong><ul style="margin:4px 0;padding-left:20px;">{sf_items}</ul></div>'

        nulled_html = ""
        if site.get("nulled_plugins"):
            np_items = "".join(f'<li style="font-size:12px;color:#991b1b;">{f}</li>' for f in site["nulled_plugins"][:5])
            nulled_html = f'<div style="margin-top:8px;background:#fee2e2;padding:8px;border-radius:6px;"><strong>&#128680; Plugins nulled/maliciosos:</strong><ul style="margin:4px 0;padding-left:20px;">{np_items}</ul></div>'

        updates_table = ""
        if plugin_rows:
            updates_table = f"""
            <table style="width:100%;border-collapse:collapse;margin-top:8px;">
                <tr style="background:#f3f4f6;">
                    <th style="padding:6px 12px;text-align:left;font-size:12px;color:#6b7280;">Plugin</th>
                    <th style="padding:6px 12px;text-align:left;font-size:12px;color:#6b7280;">Atual</th>
                    <th style="padding:6px 12px;text-align:left;font-size:12px;color:#6b7280;">Disponível</th>
                </tr>
                {plugin_rows}
            </table>"""

        admin_count = len(site.get("admin_users", []))
        active_plugins = len([p for p in site.get("plugin_list", []) if p.get("status") == "active"])
        total_plugins = len(site.get("plugin_list", []))

        sites_html += f"""
        <div style="background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:20px;margin-bottom:16px;border-left:4px solid {sc};">
            <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;">
                <h3 style="margin:0;font-size:16px;color:#111827;">{site['site']}</h3>
                <span style="background:{sc};color:#fff;padding:4px 12px;border-radius:20px;font-size:12px;font-weight:600;">{si} {sl}</span>
            </div>
            <div style="display:flex;gap:24px;margin-top:12px;flex-wrap:wrap;">
                <div style="font-size:13px;color:#6b7280;">
                    <strong>HTTP:</strong> <span style="color:{'#10b981' if site['http_status']==200 else '#ef4444'};">{site['http_status']}</span>
                </div>
                <div style="font-size:13px;color:#6b7280;">
                    <strong>WP:</strong> {site.get('wp_version','?')}
                </div>
                <div style="font-size:13px;color:#6b7280;">
                    <strong>Plugins:</strong> {active_plugins}/{total_plugins}
                </div>
                <div style="font-size:13px;color:#6b7280;">
                    <strong>Admins:</strong> {admin_count}
                </div>
                <div style="font-size:13px;color:#6b7280;">
                    <strong>Core:</strong> <span style="color:{'#10b981' if site['core_integrity']=='pass' else '#ef4444'};">{'Íntegro' if site['core_integrity']=='pass' else 'FALHOU'}</span>
                </div>
                <div style="font-size:13px;color:#6b7280;">
                    <strong>SSL:</strong> {site.get('ssl_expiry','?')[:16] if site.get('ssl_expiry','').startswith('2') else site.get('ssl_expiry','?')}
                </div>
            </div>
            {updates_table}
            {fixes_html}
            {errors_html}
            {suspicious_html}
            {nulled_html}
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#f9fafb;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
<div style="max-width:680px;margin:0 auto;padding:24px 16px;">

    <div style="background:linear-gradient(135deg,#1e293b 0%,#334155 100%);border-radius:16px;padding:32px 24px;text-align:center;margin-bottom:24px;">
        <h1 style="margin:0;color:#fff;font-size:22px;">&#128737; Relatório de Segurança WordPress</h1>
        <p style="margin:8px 0 0;color:#94a3b8;font-size:14px;">{date_fmt}</p>
    </div>

    <div style="display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap;">
        <div style="flex:1;min-width:120px;background:#fff;border-radius:12px;padding:16px;text-align:center;border:1px solid #e5e7eb;">
            <div style="font-size:28px;font-weight:700;color:{overall_color};">{overall_label}</div>
            <div style="font-size:12px;color:#6b7280;margin-top:4px;">Status Geral</div>
        </div>
        <div style="flex:1;min-width:80px;background:#fff;border-radius:12px;padding:16px;text-align:center;border:1px solid #e5e7eb;">
            <div style="font-size:28px;font-weight:700;color:#111827;">{s['total_sites']}</div>
            <div style="font-size:12px;color:#6b7280;margin-top:4px;">Sites</div>
        </div>
        <div style="flex:1;min-width:80px;background:#fff;border-radius:12px;padding:16px;text-align:center;border:1px solid #e5e7eb;">
            <div style="font-size:28px;font-weight:700;color:#10b981;">{s['ok']}</div>
            <div style="font-size:12px;color:#6b7280;margin-top:4px;">OK</div>
        </div>
        <div style="flex:1;min-width:80px;background:#fff;border-radius:12px;padding:16px;text-align:center;border:1px solid #e5e7eb;">
            <div style="font-size:28px;font-weight:700;color:#f59e0b;">{s['warning']}</div>
            <div style="font-size:12px;color:#6b7280;margin-top:4px;">Atenção</div>
        </div>
        <div style="flex:1;min-width:80px;background:#fff;border-radius:12px;padding:16px;text-align:center;border:1px solid #e5e7eb;">
            <div style="font-size:28px;font-weight:700;color:#ef4444;">{s['critical']}</div>
            <div style="font-size:12px;color:#6b7280;margin-top:4px;">Crítico</div>
        </div>
    </div>

    <div style="display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap;">
        <div style="flex:1;min-width:140px;background:#ecfdf5;border-radius:12px;padding:16px;text-align:center;">
            <div style="font-size:24px;font-weight:700;color:#059669;">{s['total_fixes']}</div>
            <div style="font-size:12px;color:#065f46;">Correções Auto-Aplicadas</div>
        </div>
        <div style="flex:1;min-width:140px;background:#fef3c7;border-radius:12px;padding:16px;text-align:center;">
            <div style="font-size:24px;font-weight:700;color:#d97706;">{s['total_issues']}</div>
            <div style="font-size:12px;color:#92400e;">Issues Detectadas</div>
        </div>
    </div>

    <h2 style="font-size:18px;color:#1e293b;margin:24px 0 12px;">Detalhes por Site</h2>

    {sites_html}

    <div style="text-align:center;margin-top:32px;padding:20px;">
        <a href="{DASHBOARD_URL}" style="display:inline-block;background:#3b82f6;color:#fff;padding:12px 32px;border-radius:8px;text-decoration:none;font-weight:600;font-size:14px;">
            &#128202; Abrir Dashboard Completa
        </a>
        <p style="margin:16px 0 0;font-size:12px;color:#9ca3af;">
            Relatório gerado automaticamente pelo agente Infra &middot; WordPress Ops<br>
            AgenciAR Digital &mdash; {date_fmt}
        </p>
    </div>

</div>
</body>
</html>"""
    return html


def send_brevo_email(subject, html_content):
    if not BREVO_API_KEY:
        print("ERROR: BREVO_API_KEY not set", file=sys.stderr)
        return False

    payload = {
        "sender": {"name": BREVO_FROM_NAME, "email": BREVO_FROM_EMAIL},
        "to": TO_EMAILS,
        "subject": subject,
        "htmlContent": html_content,
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        "https://api.brevo.com/v3/smtp/email",
        data=data,
        headers={
            "accept": "application/json",
            "content-type": "application/json",
            "api-key": BREVO_API_KEY,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode())
            print(f"Email sent! MessageId: {result.get('messageId', 'unknown')}", file=sys.stderr)
            return True
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"Brevo API error {e.code}: {body}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Email send failed: {e}", file=sys.stderr)
        return False


def update_dashboard_index(data_dir):
    files = sorted(glob.glob(os.path.join(data_dir, "*.json")), reverse=True)
    index = []
    for f in files:
        fname = os.path.basename(f)
        if fname == "index.json":
            continue
        date_str = fname.replace(".json", "")
        try:
            with open(f, "r") as fh:
                report = json.load(fh)
                summary = report.get("summary", {})
                index.append({
                    "date": date_str,
                    "file": fname,
                    "overall_status": summary.get("overall_status", "unknown"),
                    "total_sites": summary.get("total_sites", 0),
                    "ok": summary.get("ok", 0),
                    "warning": summary.get("warning", 0),
                    "critical": summary.get("critical", 0),
                    "total_issues": summary.get("total_issues", 0),
                    "total_fixes": summary.get("total_fixes", 0),
                })
        except (json.JSONDecodeError, KeyError):
            continue

    index_path = os.path.join(data_dir, "index.json")
    with open(index_path, "w") as f:
        json.dump(index, f, indent=2, ensure_ascii=False)
    print(f"Dashboard index updated: {len(index)} entries", file=sys.stderr)


def main():
    if len(sys.argv) < 2:
        print("Usage: generate-and-send-report.py <report.json>", file=sys.stderr)
        sys.exit(1)

    report_path = sys.argv[1]
    with open(report_path, "r") as f:
        report = json.load(f)

    html = generate_html(report)

    html_path = report_path.replace(".json", ".html")
    with open(html_path, "w") as f:
        f.write(html)
    print(f"HTML report saved: {html_path}", file=sys.stderr)

    s = report["summary"]
    status_emoji = {"ok": "✅", "warning": "⚠️", "critical": "🚨"}.get(s["overall_status"], "❓")
    subject = f"{status_emoji} WordPress Security — {report['date']} — {s['ok']}✓ {s['warning']}⚠ {s['critical']}✗ | {s['total_fixes']} fixes"

    sent = send_brevo_email(subject, html)

    data_dir = os.path.dirname(report_path)
    update_dashboard_index(data_dir)

    result = {
        "email_sent": sent,
        "html_report": html_path,
        "dashboard_index_updated": True,
    }
    print(json.dumps(result))


if __name__ == "__main__":
    main()
