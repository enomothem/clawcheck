import os
import sys
import subprocess
import json
import socket
from datetime import datetime
import ctypes

# 检查是否以管理员身份运行
def is_admin():
    """检查当前脚本是否以管理员权限运行"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_command(cmd):
    """执行命令并返回输出结果"""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding='gbk',  # Windows默认编码
            timeout=30
        )
        return result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return "", "命令执行超时"
    except Exception as e:
        return "", f"命令执行出错: {str(e)}"

def check_process():
    """检测OpenClaw相关进程"""
    print("\n=== 1. 检测OpenClaw进程 ===")
    cmd = 'tasklist | findstr /i "openclaw gateway"'
    stdout, stderr = run_command(cmd)
    if stdout:
        print(f"⚠️  发现异常进程:\n{stdout}")
        return "异常"
    else:
        print("✅ 未发现OpenClaw相关进程")
        return "正常"

def check_service():
    """检测OpenClaw相关系统服务/计划任务"""
    print("\n=== 2. 检测OpenClaw系统服务/计划任务 ===")
    # 检查计划任务
    cmd1 = 'schtasks /query /tn "OpenClaw Gateway" 2>NUL'
    stdout1, _ = run_command(cmd1)

    # 检查系统服务
    cmd2 = 'sc query | findstr /i "openclaw" 2>NUL'
    stdout2, _ = run_command(cmd2)

    if stdout1 or stdout2:
        print(f"⚠️  发现异常服务/计划任务:")
        if stdout1:
            print(f"计划任务: {stdout1}")
        if stdout2:
            print(f"系统服务: {stdout2}")
        return "异常"
    else:
        print("✅ 未发现OpenClaw相关服务/计划任务")
        return "正常"

def check_port():
    """检测18789端口监听状态"""
    print("\n=== 3. 检测18789端口监听状态 ===")
    cmd = 'netstat -ano | findstr ":18789"'
    stdout, _ = run_command(cmd)

    if stdout:
        lines = stdout.split('\n')
        for line in lines:
            if line.strip():
                parts = line.split()
                if len(parts) >= 4:
                    local_addr = parts[1]
                    state = parts[3] if len(parts)>=4 else ""
                    pid = parts[-1] if len(parts)>=5 else ""
                    if "0.0.0.0" in local_addr:
                        print(f"❌ 高风险: 18789端口绑定公网地址({local_addr})，状态: {state}，PID: {pid}")
                    else:
                        print(f"⚠️  中风险: 18789端口仅本地监听({local_addr})，状态: {state}，PID: {pid}")
        return "异常"
    else:
        print("✅ 18789端口未被监听")
        return "正常"

def check_files():
    """检测OpenClaw相关文件目录"""
    print("\n=== 4. 检测OpenClaw文件目录 ===")
    user_profile = os.environ.get('USERPROFILE', '')
    check_paths = [
        os.path.join(user_profile, '.openclaw'),
        os.path.join(user_profile, '.clawdbot'),
        os.path.join(user_profile, '.moltbot'),
        os.path.join(user_profile, '.molthub'),
        os.path.join(os.environ.get('ProgramFiles', ''), 'OpenClaw'),
        os.path.join(os.environ.get('ProgramFiles(x86)', ''), 'OpenClaw')
    ]

    found_paths = []
    for path in check_paths:
        if os.path.exists(path):
            found_paths.append(path)

    if found_paths:
        print(f"⚠️  发现OpenClaw相关目录:")
        for path in found_paths:
            print(f"  - {path}")
        return "异常"
    else:
        print("✅ 未发现OpenClaw相关目录")
        return "正常"

def check_nodejs():
    """检测Node.js环境（OpenClaw核心依赖）"""
    print("\n=== 5. 检测Node.js环境 ===")
    cmd = 'node -v'
    stdout, stderr = run_command(cmd)
    if stdout:
        version = stdout.strip().replace('v', '')
        version_parts = version.split('.')
        if len(version_parts)>=1 and int(version_parts[0]) >= 22:
            print(f"⚠️  发现高版本Node.js({stdout})，满足OpenClaw运行条件")
            return "异常"
        else:
            print(f"ℹ️  发现Node.js({stdout})，版本低于22，不满足OpenClaw运行条件")
            return "正常"
    else:
        print("✅ 未检测到Node.js环境")
        return "正常"

def check_config():
    """检测OpenClaw配置文件"""
    print("\n=== 6. 检测OpenClaw配置文件 ===")
    user_profile = os.environ.get('USERPROFILE', '')
    config_path = os.path.join(user_profile, '.openclaw', 'openclaw.json')

    if os.path.exists(config_path):
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)

            # 检查绑定地址
            bind_addr = config.get('gateway', {}).get('bind', '127.0.0.1')
            # 检查认证方式
            auth_type = config.get('auth', {}).get('type', 'none')

            print(f"📝 配置文件路径: {config_path}")
            print(f"   绑定地址: {bind_addr}")
            print(f"   认证方式: {auth_type}")

            if bind_addr == '0.0.0.0' or auth_type == 'none':
                print("❌ 高风险: 配置存在公网暴露/无认证风险")
                return "异常"
            else:
                print("✅ 配置文件安全合规")
                return "正常"
        except Exception as e:
            print(f"⚠️  配置文件读取失败: {str(e)}")
            return "异常"
    else:
        print("✅ 未发现OpenClaw配置文件")
        return "正常"

def generate_report(results):
    """生成检测报告"""
    print("\n" + "="*50)
    print("📋 OpenClaw Windows检测报告")
    print(f"检测时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*50)

    risk_level = "低风险"
    abnormal_count = 0

    for item, status in results.items():
        print(f"{item}: {status}")
        if status == "异常":
            abnormal_count += 1

    if abnormal_count >= 3:
        risk_level = "高风险"
    elif abnormal_count > 0:
        risk_level = "中风险"

    print(f"\n📊 整体风险等级: {risk_level}")

    if risk_level != "低风险":
        print("\n🔧 处置建议:")
        print("1. 执行命令卸载: openclaw uninstall --all --yes")
        print("2. 删除残留目录: %USERPROFILE%\\.openclaw 等相关目录")
        print("3. 关闭18789端口防火墙放行规则")
        print("4. 检查并终止相关进程/PID")
    else:
        print("\n✅ 检测结果: 未发现OpenClaw违规安装痕迹")

def main():
    """主函数"""
    print("🔍 OpenClaw Windows 检测脚本 v1.0")
    print("="*50)

    # 检查管理员权限
    if not is_admin():
        print("⚠️  警告: 建议以管理员身份运行，否则部分检测项可能不准确！")
        input("按Enter键继续（非管理员模式）...")

    # 存储检测结果
    results = {}

    # 执行各项检测
    results["进程检测"] = check_process()
    results["服务/计划任务检测"] = check_service()
    results["18789端口检测"] = check_port()
    results["文件目录检测"] = check_files()
    results["Node.js环境检测"] = check_nodejs()
    results["配置文件检测"] = check_config()

    # 生成报告
    generate_report(results)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n🛑 检测被用户中断")
    except Exception as e:
        print(f"\n\n❌ 脚本执行出错: {str(e)}")
    finally:
        input("\n按Enter键退出...")