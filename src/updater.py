# d:\桌面\cloudflare-ip-optimizer-main\src\updater.py
import logging
import os
import paramiko
import yaml
import ipaddress

START_MARKER = "##自动CF优选开始##"
END_MARKER = "##自动CF优选结束##"

def _is_ip_address(s: str) -> bool:
    """使用 ipaddress 模块检查字符串是否为有效的 IP 地址 (v4 或 v6)。"""
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

def _process_hosts_content(content: str, new_ip: str, format_style: str = 'ip_first') -> tuple[str, bool]:
    """
    处理 hosts 文件内容，替换指定块内的 IP 地址。
    如果标记不存在，则在文件末尾添加。
    返回 (更新后的内容, 是否有变化)
    """
    lines = content.splitlines()
    
    has_start = any(line.strip() == START_MARKER for line in lines)
    has_end = any(line.strip() == END_MARKER for line in lines)

    # 如果标记不存在，则在文件末尾添加
    if not has_start or not has_end:
        logging.info("Hosts 更新: 未找到标记，将在文件末尾添加。")
        # 将原内容放在前面，新块追加在后面，更安全
        new_content_list = lines + [
            "", # 确保与原内容有空行分隔
            START_MARKER,
            "# 请在此标记之间添加需要自动更新的域名，每行一个域名。",
            "# 示例: my.domain.com",
            END_MARKER,
        ]
        return "\n".join(new_content_list), True

    new_lines = []
    in_section = False
    
    for line in lines:
        if line.strip() == START_MARKER:
            in_section = True
            new_lines.append(line)
            continue
        
        if line.strip() == END_MARKER:
            in_section = False
            new_lines.append(line)
            continue
            
        if in_section:
            # 跳过空行和注释行
            if not line.strip() or line.strip().startswith('#'):
                new_lines.append(line)
                continue
            
            parts = line.strip().split()
            if not parts:
                new_lines.append(line)
                continue

            # 提取域名部分，通过过滤掉IP地址来实现
            # 这假设每行最多只有一个IP地址
            domain_parts = [p for p in parts if not _is_ip_address(p)]

            # 如果过滤后为空（说明原始行不包含可识别的域名），则保留原行
            if not domain_parts:
                new_lines.append(line)
                continue

            domains = " ".join(domain_parts)
            
            # 根据格式化风格生成新行
            if format_style == 'domain_first':
                new_lines.append(f"{domains} {new_ip}")
            else:  # 默认 ip_first
                new_lines.append(f"{new_ip} {domains}")
        else:
            new_lines.append(line)
            
    updated_content_str = "\n".join(new_lines)
    return updated_content_str, updated_content_str != content

def _execute_remote_update(config, target_name: str, remote_path: str, process_content_func, *, process_args=()):
    """通用远程更新函数，处理SSH连接、文件操作和命令执行。"""
    host = config.get('host')
    port = config.getint('port', fallback=22)
    username = config.get('username')
    password = config.get('password')
    post_command = config.get('post_update_command', fallback='').strip()

    if not remote_path:
        logging.error(f"{target_name} 更新: 未在配置文件中找到远程路径。")
        return

    logging.info(f"{target_name} 更新: 准备连接到 {host}:{port} 更新 {remote_path}")

    try:
        with paramiko.SSHClient() as ssh_client:
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(hostname=host, port=port, username=username, password=password, timeout=10)

            with ssh_client.open_sftp() as sftp:
                logging.info(f"{target_name} 更新: 正在读取远程文件 {remote_path}")
                try:
                    with sftp.open(remote_path, 'r') as remote_file:
                        content = remote_file.read().decode('utf-8')
                except FileNotFoundError:
                    logging.warning(f"{target_name} 更新: 远程文件 {remote_path} 不存在，将创建新文件。")
                    content = ""
                
                updated_content, has_changed = process_content_func(content, *process_args)
                
                if not has_changed:
                    logging.info(f"{target_name} 更新: 文件内容无需更改，跳过写入。")
                    return

                remote_tmp_path = f"/tmp/updater_tmp_{os.path.basename(remote_path)}"
                logging.info(f"{target_name} 更新: 正在写入临时文件 {remote_tmp_path}")
                with sftp.open(remote_tmp_path, 'w') as remote_file:
                    remote_file.write(updated_content)
            
            logging.info(f"{target_name} 更新: 正在移动临时文件以覆盖原文件")
            stdin, stdout, stderr = ssh_client.exec_command(f"mv -f {remote_tmp_path} {remote_path}")
            exit_status = stdout.channel.recv_exit_status()
            if exit_status == 0:
                logging.info(f"{target_name} 更新: 成功更新文件。")
                if post_command:
                    logging.info(f"{target_name} 更新: 正在执行更新后命令: '{post_command}'")
                    stdin, stdout, stderr = ssh_client.exec_command(post_command)
                    if stdout.channel.recv_exit_status() != 0:
                        logging.error(f"{target_name} 更新: 更新后命令执行失败: {stderr.read().decode('utf-8').strip()}")
            else:
                logging.error(f"{target_name} 更新: 移动文件失败: {stderr.read().decode('utf-8').strip()}")

    except paramiko.AuthenticationException:
        logging.error(f"{target_name} 更新: SSH 认证失败，请检查用户名和密码。")
    except Exception as e:
        logging.error(f"{target_name} 更新: 发生错误: {e}")

def _process_adguard_content(content: str, new_ip: str) -> tuple[str, bool]:
    """
    处理 AdGuard Home 配置文件内容，替换 rewrites 列表中的 IP 地址。
    返回 (更新后的内容, 是否有变化)
    """
    try:
        data = yaml.safe_load(content)
        if not isinstance(data, dict):
            logging.error("AdGuard Home 更新: 配置文件不是一个有效的YAML字典。")
            return content, False
        
        # 使用 setdefault 安全地获取或创建嵌套的键
        filtering = data.setdefault('filtering', {})
        rewrites = filtering.setdefault('rewrites', [])

        if not isinstance(rewrites, list):
            logging.error(f"AdGuard Home 更新: 'filtering.rewrites' 应该是一个列表，但它是 {type(rewrites)}。")
            return content, False

        if not rewrites:
            logging.info("AdGuard Home 更新: 'rewrites' 列表为空，没有域名可以更新。请在 AdGuard Home 界面添加 DNS 重写规则。")
            return content, False

        changed = False
        for entry in rewrites:
            if isinstance(entry, dict) and 'domain' in entry:
                if entry.get('answer') != new_ip:
                    entry['answer'] = new_ip
                    changed = True
        
        if changed:
            logging.info(f"AdGuard Home 更新: 已将 {len(rewrites)} 条重写规则的 IP 地址更新为 {new_ip}")
            return yaml.dump(data, sort_keys=False, allow_unicode=True), True
        else:
            logging.info("AdGuard Home 更新: 所有重写规则的 IP 地址已是最新，无需更新。")
            return content, False

    except yaml.YAMLError as e:
        logging.error(f"AdGuard Home 更新: 解析 YAML 配置文件时出错: {e}")
        return content, False

def update_openwrt_hosts(config, best_ip: str):
    """
    通过 SSH 连接到 OpenWRT 或 MosDNS 并更新 hosts 文件。
    """
    if not config.getboolean('enabled', fallback=False):
        return

    target = config.get('target', fallback='openwrt')
    remote_path = config.get(f"{target}_hosts_path")

    # 根据目标确定 hosts 文件格式
    format_style = 'domain_first' if target == 'mosdns' else 'ip_first'
    logging.info(f"Hosts ({target}) 更新: 使用格式 '{format_style}'。")

    _execute_remote_update(
        config,
        target_name=f"Hosts ({target})",
        remote_path=remote_path,
        process_content_func=_process_hosts_content,
        process_args=(best_ip, format_style)
    )

def update_adguard_hosts(config, best_ip: str):
    """
    通过 SSH 连接到 OpenWRT 并更新 AdGuard Home 配置文件。
    """
    if not config.getboolean('enabled', fallback=False):
        return

    remote_path = config.get('adguardhome_config_path')
    _execute_remote_update(
        config,
        target_name="AdGuard Home",
        remote_path=remote_path,
        process_content_func=_process_adguard_content,
        process_args=(best_ip,)
    )
