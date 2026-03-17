use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File};
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use chrono::Local;
use serde::Serialize;
use serde_json::Value;

#[derive(Clone, Serialize)]
struct CheckResult {
    status: String,
    details: Vec<String>,
}

#[cfg(target_os = "windows")]
fn run_command(cmd: &str) -> (String, String) {
    use encoding_rs::GBK;
    let output = Command::new("cmd")
        .args(["/C", cmd])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();
    match output {
        Ok(out) => {
            let (s, _, _) = GBK.decode(&out.stdout);
            let (e, _, _) = GBK.decode(&out.stderr);
            (s.trim().to_string(), e.trim().to_string())
        }
        Err(e) => ("".to_string(), format!("{}", e)),
    }
}

#[cfg(not(target_os = "windows"))]
fn run_command(cmd: &str) -> (String, String) {
    let output = Command::new("sh")
        .args(["-c", cmd])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();
    match output {
        Ok(out) => {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let e = String::from_utf8_lossy(&out.stderr).trim().to_string();
            (s, e)
        }
        Err(e) => ("".to_string(), format!("{}", e)),
    }
}

fn is_windows() -> bool {
    cfg!(target_os = "windows")
}

fn is_macos() -> bool {
    cfg!(target_os = "macos")
}

fn check_process() -> CheckResult {
    let cmd = if is_windows() {
        r#"tasklist | findstr /i "openclaw gateway""#.to_string()
    } else if is_macos() {
        r#"ps aux | grep -Ei "openclaw|gateway" | grep -v grep"#.to_string()
    } else {
        r#"ps aux | grep -Ei "openclaw|gateway" | grep -v grep"#.to_string()
    };
    let (stdout, _) = run_command(&cmd);
    if stdout.is_empty() {
        CheckResult {
            status: "正常".to_string(),
            details: vec!["未发现OpenClaw相关进程".to_string()],
        }
    } else {
        let mut d = vec!["发现异常进程".to_string()];
        d.push(stdout);
        CheckResult {
            status: "异常".to_string(),
            details: d,
        }
    }
}

fn check_service() -> CheckResult {
    let (s1, s2) = if is_windows() {
        let (a, _) = run_command(r#"schtasks /query /tn "OpenClaw Gateway" 2>NUL"#);
        let (b, _) = run_command(r#"sc query | findstr /i "openclaw" 2>NUL"#);
        (a, b)
    } else if is_macos() {
        let (launchd, _) = run_command(r#"launchctl list 2>/dev/null | grep -i openclaw"#);
        let (cron, _) = run_command(r#"crontab -l 2>/dev/null | grep -i openclaw"#);
        (format!("{}\n{}", launchd, cron).trim().to_string(), String::new())
    } else {
        // systemd 和 SysV 双路径尝试 + crontab 检查
        let (systemd, _) = run_command(r#"systemctl list-units --type=service --all 2>/dev/null | grep -i openclaw"#);
        let (sysv, _) = run_command(r#"service --status-all 2>/dev/null | grep -i openclaw"#);
        let (cron, _) = run_command(r#"crontab -l 2>/dev/null | grep -i openclaw"#);
        (format!("{}\n{}", systemd, cron).trim().to_string(), sysv)
    };
    if s1.is_empty() && s2.is_empty() {
        CheckResult {
            status: "正常".to_string(),
            details: vec!["未发现OpenClaw相关服务/计划任务".to_string()],
        }
    } else {
        let mut details = vec!["发现异常服务/计划任务".to_string()];
        if !s1.is_empty() {
            details.push(format!("计划任务: {}", s1));
        }
        if !s2.is_empty() {
            details.push(format!("系统服务: {}", s2));
        }
        CheckResult {
            status: "异常".to_string(),
            details,
        }
    }
}

fn check_port() -> CheckResult {
    let (stdout, _) = if is_windows() {
        run_command(r#"netstat -ano | findstr ":18789""#)
    } else if is_macos() {
        let (lsof_out, _) = run_command(r#"lsof -nP -iTCP:18789 -sTCP:LISTEN 2>/dev/null"#);
        if lsof_out.is_empty() {
            run_command(r#"netstat -anv 2>/dev/null | grep ".18789""#)
        } else {
            (lsof_out, String::new())
        }
    } else {
        // 优先 ss，回退 netstat
        let (ss_out, _) = run_command(r#"ss -ltnp 2>/dev/null | grep ":18789""#);
        if ss_out.is_empty() {
            run_command(r#"netstat -tunlp 2>/dev/null | grep ":18789""#)
        } else {
            (ss_out, String::new())
        }
    };
    if stdout.is_empty() {
        CheckResult {
            status: "正常".to_string(),
            details: vec!["18789端口未被监听".to_string()],
        }
    } else {
        let mut details = vec![];
        for line in stdout.lines() {
            if is_windows() {
                let p: Vec<&str> = line.split_whitespace().collect();
                if p.len() >= 4 {
                    let local_addr = p[1].to_string();
                    let state = p.get(3).cloned().unwrap_or("").to_string();
                    let pid = p.last().cloned().unwrap_or("").to_string();
                    if local_addr.contains("0.0.0.0") {
                        details.push(format!("高风险: 18789绑定公网地址({}), 状态: {}, PID: {}", local_addr, state, pid));
                    } else {
                        details.push(format!("中风险: 18789本地监听({}), 状态: {}, PID: {}", local_addr, state, pid));
                    }
                }
            } else {
                // 以是否对外绑定判定风险
                let line_l = line.to_lowercase();
                let high = line_l.contains("0.0.0.0:18789")
                    || line_l.contains("[::]:18789")
                    || line_l.contains("*:18789");
                if high {
                    details.push(format!("高风险: 18789对外监听 -> {}", line.trim()));
                } else {
                    details.push(format!("中风险: 18789本地监听/限定地址 -> {}", line.trim()));
                }
            }
        }
        CheckResult {
            status: "异常".to_string(),
            details,
        }
    }
}

fn check_files() -> CheckResult {
    let mut candidates: Vec<PathBuf> = vec![];
    if is_windows() {
        let user_profile = env::var("USERPROFILE").unwrap_or_default();
        candidates.push(PathBuf::from(&user_profile).join(".openclaw"));
        candidates.push(PathBuf::from(&user_profile).join(".clawdbot"));
        candidates.push(PathBuf::from(&user_profile).join(".moltbot"));
        candidates.push(PathBuf::from(&user_profile).join(".molthub"));
        if let Ok(pf) = env::var("ProgramFiles") {
            candidates.push(PathBuf::from(pf).join("OpenClaw"));
        }
        if let Ok(pfx86) = env::var("ProgramFiles(x86)") {
            candidates.push(PathBuf::from(pfx86).join("OpenClaw"));
        }
    } else if is_macos() {
        let home = env::var("HOME").unwrap_or_default();
        candidates.push(PathBuf::from(&home).join(".openclaw"));
        candidates.push(PathBuf::from(&home).join(".clawdbot"));
        candidates.push(PathBuf::from(&home).join(".moltbot"));
        candidates.push(PathBuf::from(&home).join(".molthub"));
        candidates.push(PathBuf::from("/Applications").join("OpenClaw.app"));
    } else {
        let home = env::var("HOME").unwrap_or_default();
        candidates.push(PathBuf::from(&home).join(".openclaw"));
        candidates.push(PathBuf::from(&home).join(".clawdbot"));
        candidates.push(PathBuf::from(&home).join(".moltbot"));
        candidates.push(PathBuf::from(&home).join(".molthub"));
        candidates.push(PathBuf::from("/opt").join("OpenClaw"));
        candidates.push(PathBuf::from("/usr/local").join("OpenClaw"));
    }
    let mut found = vec![];
    for p in candidates {
        if p.exists() {
            found.push(p.display().to_string());
        }
    }
    if found.is_empty() {
        CheckResult {
            status: "正常".to_string(),
            details: vec!["未发现OpenClaw相关目录".to_string()],
        }
    } else {
        let mut d = vec!["发现OpenClaw相关目录".to_string()];
        d.extend(found.into_iter().map(|s| format!("- {}", s)));
        CheckResult {
            status: "异常".to_string(),
            details: d,
        }
    }
}

fn check_nodejs() -> CheckResult {
    let (stdout, _) = run_command("node -v");
    if stdout.is_empty() {
        CheckResult {
            status: "正常".to_string(),
            details: vec!["未检测到Node.js环境".to_string()],
        }
    } else {
        let v = stdout.trim().trim_start_matches('v').to_string();
        let major = v.split('.').next().and_then(|x| x.parse::<i32>().ok()).unwrap_or(0);
        if major >= 22 {
            CheckResult {
                status: "异常".to_string(),
                details: vec![format!("发现高版本Node.js({}), 满足OpenClaw运行条件", stdout)],
            }
        } else {
            CheckResult {
                status: "正常".to_string(),
                details: vec![format!("发现Node.js({}), 版本低于22", stdout)],
            }
        }
    }
}

fn read_file_to_string(p: &PathBuf) -> Option<String> {
    let mut f = File::open(p).ok()?;
    let mut s = String::new();
    f.read_to_string(&mut s).ok()?;
    Some(s)
}

fn check_config() -> CheckResult {
    let base = if is_windows() {
        env::var("USERPROFILE").unwrap_or_default()
    } else {
        env::var("HOME").unwrap_or_default()
    };
    let path = PathBuf::from(base).join(".openclaw").join("openclaw.json");
    if !path.exists() {
        return CheckResult {
            status: "正常".to_string(),
            details: vec!["未发现OpenClaw配置文件".to_string()],
        };
    }
    let content = match read_file_to_string(&path) {
        Some(s) => s,
        None => {
            return CheckResult {
                status: "异常".to_string(),
                details: vec!["配置文件读取失败".to_string()],
            }
        }
    };
    let v: Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => {
            return CheckResult {
                status: "异常".to_string(),
                details: vec!["配置文件解析失败".to_string()],
            }
        }
    };
    let bind_addr = v.get("gateway").and_then(|g| g.get("bind")).and_then(|b| b.as_str()).unwrap_or("127.0.0.1").to_string();
    let auth_type = v.get("auth").and_then(|a| a.get("type")).and_then(|t| t.as_str()).unwrap_or("none").to_string();
    let mut details = vec![
        format!("配置文件路径: {}", path.display()),
        format!("绑定地址: {}", bind_addr),
        format!("认证方式: {}", auth_type),
    ];
    if bind_addr == "0.0.0.0" || auth_type == "none" {
        details.insert(0, "高风险: 配置存在公网暴露/无认证风险".to_string());
        CheckResult {
            status: "异常".to_string(),
            details,
        }
    } else {
        details.insert(0, "配置文件安全合规".to_string());
        CheckResult {
            status: "正常".to_string(),
            details,
        }
    }
}

fn risk_level(results: &BTreeMap<String, CheckResult>) -> (String, usize) {
    let mut abnormal = 0usize;
    for r in results.values() {
        if r.status == "异常" {
            abnormal += 1;
        }
    }
    let level = if abnormal >= 3 {
        "高风险"
    } else if abnormal > 0 {
        "中风险"
    } else {
        "低风险"
    };
    (level.to_string(), abnormal)
}

fn html_report(results: &BTreeMap<String, CheckResult>) -> String {
    let time = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let (level, _) = risk_level(results);
    let mut rows = String::new();
    for (k, v) in results {
        let cls = if v.status == "异常" { "bad" } else { "ok" };
        let mut detail_html = String::new();
        for d in &v.details {
            detail_html.push_str(&format!("<div class=\"detail-item\">{}</div>", html_escape(d)));
        }
        rows.push_str(&format!(
            "<tr><td class=\"item\">{}</td><td class=\"status {}\">{}</td><td class=\"details\">{}</td></tr>",
            html_escape(k),
            cls,
            v.status,
            detail_html
        ));
    }
    let suggestions = if level != "低风险" {
        "<ul>
            <li>执行卸载命令: openclaw uninstall --all --yes</li>
            <li>删除残留目录: 用户目录下 .openclaw 等</li>
            <li>清理或限制18789端口对外访问</li>
            <li>检查并终止相关进程</li>
         </ul>"
            .to_string()
    } else {
        "<div>未发现违规安装痕迹</div>".to_string()
    };
    format!(
        r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OpenClaw 系统检测报告</title>
<style>
html,body{{margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,"Noto Sans",sans-serif;color:#1f2937;background:#f8fafc}}
.container{{max-width:1000px;margin:32px auto;padding:0 16px}}
.title{{font-size:24px;font-weight:600;margin-bottom:8px}}
.subtitle{{color:#6b7280;margin-bottom:24px}}
.card{{background:#fff;border:1px solid #e5e7eb;border-radius:8px;box-shadow:0 1px 2px rgba(0,0,0,0.04);overflow:hidden}}
.header{{display:flex;justify-content:space-between;align-items:center;padding:16px;border-bottom:1px solid #e5e7eb}}
.badge{{padding:4px 10px;border-radius:999px;font-size:12px;font-weight:600}}
.badge.low{{background:#ecfdf5;color:#065f46}}
.badge.mid{{background:#fffbeb;color:#92400e}}
.badge.high{{background:#fef2f2;color:#991b1b}}
table{{width:100%;border-collapse:collapse}}
th,td{{padding:12px;border-bottom:1px solid #e5e7eb;vertical-align:top;text-align:left}}
th{{background:#f9fafb;font-weight:600;color:#374151}}
.status.ok{{color:#065f46}}
.status.bad{{color:#991b1b}}
.item{{width:220px;white-space:nowrap}}
.details{{font-size:14px;color:#374151}}
.detail-item{{margin:2px 0}}
.footer{{padding:16px}}
</style>
</head>
<body>
  <div class="container">
    <div class="title">OpenClaw 系统检测报告</div>
    <div class="subtitle">检测时间: {time}</div>
    <div class="card">
      <div class="header">
        <div>检测结果</div>
        <div class="badge {badge_cls}">{level}</div>
      </div>
      <div>
        <table>
          <thead>
            <tr><th>检测项</th><th>状态</th><th>详情</th></tr>
          </thead>
          <tbody>
            {rows}
          </tbody>
        </table>
      </div>
      <div class="footer">
        <div style="font-weight:600;margin-bottom:8px">处置建议</div>
        {suggestions}
      </div>
    </div>
  </div>
</body>
</html>
"#,
        time = html_escape(&time),
        level = level,
        rows = rows,
        suggestions = suggestions,
        badge_cls = match level.as_str() {
            "高风险" => "badge high",
            "中风险" => "badge mid",
            _ => "badge low",
        }
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn main() {
    let mut results: BTreeMap<String, CheckResult> = BTreeMap::new();
    results.insert("进程检测".to_string(), check_process());
    results.insert("服务/计划任务检测".to_string(), check_service());
    results.insert("18789端口检测".to_string(), check_port());
    results.insert("文件目录检测".to_string(), check_files());
    results.insert("Node.js环境检测".to_string(), check_nodejs());
    results.insert("配置文件检测".to_string(), check_config());

    let html = html_report(&results);
    let out_path = PathBuf::from("clawcheck_report.html");
    let _ = fs::write(&out_path, html);
    println!("报告已生成: {}", out_path.display());
}

