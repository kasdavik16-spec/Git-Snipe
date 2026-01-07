
 
import os
import re
import json
import time
import shutil
import tempfile
import subprocess
import asyncio
from datetime import datetime
 
if os.name == "nt":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
 

BOT_TOKEN ="" 
ADMIN_ID = ""
 
MAX_REPO_MB = 80
MAX_FILE_MB = 2
CLONE_TIMEOUT_SEC = 300
SCAN_TIMEOUT_SEC = 240
SHOW_PER_RISK = 5
 
SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__", ".mypy_cache",
    "dist", "build", "target", ".idea", ".vscode", ".tox", ".pytest_cache",
}
SCAN_EXTS = {
    ".py", ".js", ".ts", ".json", ".yml", ".yaml", ".env", ".txt", ".md",
    ".java", ".cpp", ".c", ".h", ".go", ".rs", ".php", ".rb", ".sh", ".bat",
    ".cs", ".swift", ".toml", ".ini", ".properties", ".gradle", ".kts",
    ".conf", ".config", ".xml",
}
SCAN_FILENAMES = {
    ".env", "Dockerfile", "docker-compose.yml", "Makefile", "requirements.txt",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "pip.conf", "npmrc", ".npmrc",
    "settings.gradle", "gradle.properties", "application.properties",
}
 
PATTERNS = {
    "aws_access_key_id": r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",
    "aws_secret_access_key_kw": r"(?i)\baws[_-]?(?:secret|secret_access|secretaccess)[_-]?key\b\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]",
    "aws_session_token_kw": r"(?i)\baws[_-]?session[_-]?token\b\s*[:=]\s*['\"]([A-Za-z0-9/+=]{80,})['\"]",
 
    "github_pat": r"\bghp_[A-Za-z0-9]{36}\b|\bgho_[A-Za-z0-9]{36}\b|\bghs_[A-Za-z0-9]{36}\b|\bghu_[A-Za-z0-9]{36}\b",
    "github_fine_grained_pat": r"\bgithub_pat_[A-Za-z0-9_]{80,}\b",
    "gitlab_pat": r"\bglpat-[A-Za-z0-9\-_=]{20,}\b",
 
    "slack_token": r"\bxox[baprs]-[0-9A-Za-z]{10,48}\b",
    "slack_webhook": r"https://hooks\.slack\.com/services/[A-Z0-9]{6,}/[A-Z0-9]{6,}/[A-Za-z0-9]{20,}",
 
    "discord_token": r"\b(?:mfa\.[A-Za-z0-9_-]{80,})\b|\b([A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27})\b",
    "discord_webhook": r"https://discord(?:app)?\.com/api/webhooks/\d{16,20}/[A-Za-z0-9_-]{20,}",
 
    "stripe_live_secret_key": r"\bsk_live_[0-9a-zA-Z]{24,}\b",
    "stripe_restricted_key": r"\brk_live_[0-9a-zA-Z]{24,}\b",
 
    "twilio_account_sid": r"\bAC[a-f0-9]{32}\b",
    "twilio_api_key": r"\bSK[a-f0-9]{32}\b",
    "twilio_auth_token_kw": r"(?i)\btwilio\b.*\b(auth[_-]?token)\b\s*[:=]\s*['\"]([a-f0-9]{32})['\"]",
 
    "sendgrid_api_key": r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{40,}\b",
    "mailgun_api_key": r"\bkey-[a-f0-9]{32}\b",
 
    "google_api_key": r"\bAIza[0-9A-Za-z\-_]{35}\b",
    "gcp_service_account": r"(?s)\"type\"\s*:\s*\"service_account\".*?\"private_key\"\s*:\s*\"-----BEGIN PRIVATE KEY-----",
    "firebase_server_key": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,}",
 
    "azure_storage_account_key_kw": r"(?i)\bazure\b.*\b(storage[_-]?account[_-]?key|account[_-]?key)\b\s*[:=]\s*['\"]([A-Za-z0-9+/=]{40,})['\"]",
    "azure_sas_token": r"\bsv=\d{4}-\d{2}-\d{2}&ss=[a-z]+&srt=[a-z]+&sp=[a-z]+&se=\d{4}-\d{2}-\d{2}T\d{2}%3A\d{2}%3A\d{2}Z&st=\d{4}-\d{2}-\d{2}T\d{2}%3A\d{2}%3A\d{2}Z&spr=https?&sig=[A-Za-z0-9%]{20,}\b",
 
    "jwt_token": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    "jwt_secret_kw": r"(?i)\bjwt[_-]?secret\b\s*[:=]\s*['\"]([^'\"\s]{10,})['\"]",
 
    "database_url": r"(?i)\b(mysql|postgres(?:ql)?|mongodb|redis)://[^ \n'\"<>]+",
    "database_password_kw": r"(?i)\b(db|database)[_-]?(pass|password)\b\s*[:=]\s*['\"]([^'\"\s]{6,})['\"]",
    "password_kw": r"(?i)\b(password|passwd|pwd)\b\s*[:=]\s*['\"]([^'\"\s]{6,})['\"]",
 
    "private_key_block": r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP|PRIVATE) (?:PRIVATE )?KEY-----",
    "ssh_private_key": r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "pem_private_key": r"-----BEGIN PRIVATE KEY-----",
 
    "npm_token": r"(?i)\b(npm[_-]?token|_authToken)\b\s*[:=]\s*['\"]([A-Za-z0-9_-]{20,})['\"]",
    "docker_auth_base64": r"(?i)\"auth\"\s*:\s*\"([A-Za-z0-9+/=]{20,})\"",
 
    "generic_api_key_kw": r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]",
}
 
RISK_LEVELS = {
    "🔴 КРИТИЧЕСКИЙ": {
        "private_key_block", "ssh_private_key", "pem_private_key",
        "aws_secret_access_key_kw", "github_pat", "github_fine_grained_pat", "gitlab_pat",
        "sendgrid_api_key", "stripe_live_secret_key",
        "gcp_service_account",
    },
    "🟡 ВЫСОКИЙ": {
        "aws_access_key_id", "aws_session_token_kw",
        "google_api_key", "slack_webhook", "discord_webhook",
        "twilio_auth_token_kw", "twilio_account_sid", "twilio_api_key",
        "azure_storage_account_key_kw", "azure_sas_token",
        "jwt_token", "jwt_secret_kw",
        "database_url", "database_password_kw",
    },
    "🟢 СРЕДНИЙ": {
        "password_kw", "slack_token", "discord_token", "mailgun_api_key",
        "npm_token", "docker_auth_base64",
        "generic_api_key_kw",
    },
}
 
def risk_of(secret_type: str) -> str:
    for level, types in RISK_LEVELS.items():
        if secret_type in types:
            return level
    return "⚪️ НИЗКИЙ"
 
def mask_value(secret_type: str, value: str) -> str:
    if secret_type in {"private_key_block", "ssh_private_key", "pem_private_key", "gcp_service_account"}:
        return "***PRIVATE KEY / SERVICE ACCOUNT***"
    if not value or len(value) <= 10:
        return "***"
    return value[:4] + "***" + value[-4:]
 
def now_ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
 
def is_probably_binary(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            chunk = f.read(2048)
        return b"\x00" in chunk
    except Exception:
        return True
 
def file_ok_to_scan(path: str) -> bool:
    try:
        size = os.path.getsize(path)
        if size > MAX_FILE_MB * 1024 * 1024:
            return False
    except Exception:
        return False
 
    base = os.path.basename(path)
    ext = os.path.splitext(base)[1].lower()
    return (base in SCAN_FILENAMES) or (ext in SCAN_EXTS)
 
class SecretScanner:
    def __init__(self):
        self.reset_stats()
        self._compiled = {k: re.compile(v) for k, v in PATTERNS.items()}
 
    def reset_stats(self):
        self.stats = {"files_scanned": 0, "secrets_found": 0, "start_time": 0, "end_time": 0}
 
    def scan_text(self, text: str, file_path: str):
        findings = []
        for stype, cregex in self._compiled.items():
            try:
                for m in cregex.finditer(text):
                    raw = m.group(0)
                    if m.groups():
                        raw = m.group(m.lastindex or 1)
 
                    line_num = text.count("\n", 0, m.start()) + 1
                    line_start = text.rfind("\n", 0, m.start())
                    line_end = text.find("\n", m.start())
                    line_start = 0 if line_start == -1 else line_start + 1
                    line_end = len(text) if line_end == -1 else line_end
                    context = text[line_start:line_end].strip()
                    if len(context) > 160:
                        context = context[:160] + "..."
 
                    findings.append({
                        "file": os.path.basename(file_path),
                        "path": file_path,
                        "line": line_num,
                        "type": stype,
                        "risk": risk_of(stype),
                        "value": mask_value(stype, raw),
                        "context": context,
                        "timestamp": now_ts(),
                    })
            except Exception:
                continue
        return findings
 
    def scan_file(self, path: str):
        if not file_ok_to_scan(path) or is_probably_binary(path):
            return []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except Exception:
            return []
        self.stats["files_scanned"] += 1
        res = self.scan_text(text, path)
        self.stats["secrets_found"] += len(res)
        return res
 
    def scan_directory(self, root_dir: str):
        all_findings = []
        for root, dirs, files in os.walk(root_dir):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
            for fn in files:
                all_findings.extend(self.scan_file(os.path.join(root, fn)))
        return all_findings
 
    def _dir_size_bytes(self, root_dir: str) -> int:
        total = 0
        for root, _, files in os.walk(root_dir):
            for fn in files:
                try:
                    total += os.path.getsize(os.path.join(root, fn))
                except Exception:
                    pass
        return total
 
    def scan_git_repo(self, repo_url: str):
        temp_dir = tempfile.mkdtemp(prefix="scan_")
        self.reset_stats()
        self.stats["start_time"] = time.time()
 
        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"
 
        try:
            subprocess.run(["git", "--version"], capture_output=True, text=True, check=True)
            res = subprocess.run(
                ["git", "clone", "--depth", "1", "--single-branch", "--no-tags", repo_url, temp_dir],
                capture_output=True, text=True, timeout=CLONE_TIMEOUT_SEC, env=env,
            )
            if res.returncode != 0:
                msg = (res.stderr or res.stdout or "unknown git error").strip()
                return [{
                    "file": "git", "path": "git", "line": 0, "type": "git_error",
                    "risk": "🔴 КРИТИЧЕСКИЙ", "value": msg[:180],
                    "context": f"Failed to clone: {repo_url}", "timestamp": now_ts(),
                }]
 
            size = self._dir_size_bytes(temp_dir)
            if size > MAX_REPO_MB * 1024 * 1024:
                return [{
                    "file": "repo", "path": "repo", "line": 0, "type": "repo_too_large",
                    "risk": "🟡 ВЫСОКИЙ", "value": f">{MAX_REPO_MB}MB",
                    "context": "Repository is too large to scan safely in this bot config",
                    "timestamp": now_ts(),
                }]
 
            return self.scan_directory(temp_dir)
 
        except subprocess.TimeoutExpired:
            return [{
                "file": "timeout", "path": "timeout", "line": 0, "type": "timeout",
                "risk": "🟡 ВЫСОКИЙ", "value": f"{CLONE_TIMEOUT_SEC}s",
                "context": "git clone timed out", "timestamp": now_ts(),
            }]
        except Exception as e:
            return [{
                "file": "error", "path": "error", "line": 0, "type": "exception",
                "risk": "🔴 КРИТИЧЕСКИЙ", "value": str(e)[:180],
                "context": "Unexpected error while scanning", "timestamp": now_ts(),
            }]
        finally:
            self.stats["end_time"] = time.time()
            shutil.rmtree(temp_dir, ignore_errors=True)
 
    def generate_report_html(self, findings):
        if not findings:
            return "✅ <b>Секреты не найдены!</b>"
 
        by_risk = {}
        for f in findings:
            by_risk.setdefault(f["risk"], []).append(f)
 
        risk_order = ["🔴 КРИТИЧЕСКИЙ", "🟡 ВЫСОКИЙ", "🟢 СРЕДНИЙ", "⚪️ НИЗКИЙ"]
        total = 0
 
        lines = []
        lines.append("📊 <b>ОТЧЁТ О СКАНИРОВАНИИ</b>")
        lines.append("<code>" + "=" * 40 + "</code>")
 
        for r in risk_order:
            if r not in by_risk:
                continue
            items = by_risk[r]
            total += len(items)
 
            lines.append(f"\n<b>{r}</b>: {len(items)}")
            lines.append("<code>" + "-" * 28 + "</code>")
 
            for i, it in enumerate(items[:SHOW_PER_RISK], 1):
                file_line = f"{it['file']}:{it['line']}"
                lines.append(f"{i}) <b>{it['type']}</b>")
                lines.append(f"   📁 <code>{file_line}</code>")
                lines.append(f"   🔑 <code>{it['value']}</code>")
                if it.get("context"):
                    safe_ctx = it["context"].replace("<", "&lt;").replace(">", "&gt;")
                    lines.append(f"   📝 <code>{safe_ctx}</code>")
 
        lines.append("\n<b>📈 СТАТИСТИКА</b>")
        lines.append(f"📂 Файлов проверено: <b>{self.stats['files_scanned']}</b>")
        lines.append(f"🔍 Найдено секретов: <b>{total}</b>")
 
        if "🔴 КРИТИЧЕСКИЙ" in by_risk:
            overall = "🔴 КРИТИЧЕСКИЙ"
        elif "🟡 ВЫСОКИЙ" in by_risk:
            overall = "🟡 ВЫСОКИЙ"
        elif "🟢 СРЕДНИЙ" in by_risk:
            overall = "🟢 СРЕДНИЙ"
        else:
            overall = "⚪️ НИЗКИЙ"
        lines.append(f"⚠️ Общий риск: <b>{overall}</b>")
 
        return "\n".join(lines)
 
    def recommendations_text(self, findings):
        if not findings:
            return ""
        rec = ["💡 <b>Рекомендации</b>"]
        if any(f["risk"] == "🔴 КРИТИЧЕСКИЙ" for f in findings):
            rec.append("• Срочно <b>ротируйте</b> критические секреты (ключи/токены/приватные ключи).")
        if any(f["risk"] == "🟡 ВЫСОКИЙ" for f in findings):
            rec.append("• Замените высокорисковые ключи и вынесите конфиги в переменные окружения.")
        rec.append("• Добавьте <code>.env</code> в <code>.gitignore</code>, включите CI/pre-commit сканер.")
        return "\n".join(rec)
 
def looks_like_git_url(url: str) -> bool:
    url = url.strip()
    return bool(url) and (
        url.startswith("https://github.com/")
        or url.startswith("https://gitlab.com/")
        or url.startswith("https://bitbucket.org/")
        or url.startswith("git@")
        or url.startswith("ssh://git@")
        or url.endswith(".git")
    )
 
def main():
    if not BOT_TOKEN:
        print("❌ BOT_TOKEN не задан. Задай переменную окружения BOT_TOKEN.")
        return
 
    from telegram import Update
    from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
 
    scanner = SecretScanner()
    user_state = {}
 
    async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
        await update.message.reply_text(
            "👋 Привет!\n"
            "Я сканирую репозитории и ищу утечки секретов.\n\n"
            "Команды:\n"
            "/scan — начать сканирование\n"
            "/help — помощь\n"
            "/cancel — отмена\n\n"
            "⚠️ Используй только для своих репозиториев или с разрешения владельца.",
            disable_web_page_preview=True,
        )
 
    async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
        await update.message.reply_text(
            "🆘 Как пользоваться:\n"
            "1) /scan\n"
            "2) пришли ссылку на репозиторий\n"
            "3) получишь отчёт\n\n"
            "Секреты в отчёте маскируются.",
            disable_web_page_preview=True,
        )
 
    async def cmd_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
        uid = update.effective_user.id
        user_state[uid] = "wait_url"
        await update.message.reply_text(
            "🔗 Пришли ссылку на репозиторий.\nПример: https://github.com/user/repo\n/cancel — отмена",
            disable_web_page_preview=True,
        )
 
    async def cmd_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
        uid = update.effective_user.id
        user_state.pop(uid, None)
        await update.message.reply_text("❌ Отменено.")
 
    async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
        uid = update.effective_user.id
        text = (update.message.text or "").strip()
 
        if user_state.get(uid) != "wait_url":
            await update.message.reply_text("Напиши /scan чтобы начать.")
            return
 
        user_state.pop(uid, None)
 
        if not looks_like_git_url(text):
            await update.message.reply_text("❌ Похоже, это не ссылка на git-репозиторий. Попробуй ещё раз: /scan")
            return
 
        status = await update.message.reply_text("🔄 Клонирую и сканирую…")
 
        try:
            findings = await asyncio.wait_for(asyncio.to_thread(scanner.scan_git_repo, text), timeout=SCAN_TIMEOUT_SEC)
 
            report = scanner.generate_report_html(findings)
            await update.message.reply_text(report, parse_mode="HTML", disable_web_page_preview=True)
 
            rec = scanner.recommendations_text(findings)
            if rec:
                await update.message.reply_text(rec, parse_mode="HTML", disable_web_page_preview=True)
 
            if ADMIN_ID and uid == ADMIN_ID:
                payload = {"repo": text, "stats": scanner.stats, "findings": findings}
                js = json.dumps(payload, ensure_ascii=False, indent=2)
                if len(js) > 3500:
                    js = js[:3500] + "\n...\n(truncated)"
                js = js.replace("<", "&lt;").replace(">", "&gt;")
                await update.message.reply_text(
                    "<b>🧾 JSON (admin preview)</b>\n<code>" + js + "</code>",
                    parse_mode="HTML",
                )
 
        except asyncio.TimeoutError:
            await update.message.reply_text("⏱ Сканирование заняло слишком много времени. Попробуй позже.")
        except Exception as e:
            await update.message.reply_text("❌ Ошибка: " + str(e)[:200])
        finally:
            try:
                await status.delete()
            except Exception:
                pass
 
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("scan", cmd_scan))
    app.add_handler(CommandHandler("cancel", cmd_cancel))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
 
    print("🤖 Bot running…")
    app.run_polling()
 
if __name__ == "__main__":
    main()