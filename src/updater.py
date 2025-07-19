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

def read_remote_file(config, target: str) -> tuple[str, bool]:
    """
    通过 SSH 连接到远程设备并读取指定文件的内容。
    返回 (文件内容, 是否成功) 的元组。
    """
    host = config.get('host')
    port = config.getint('port', fallback=22)
    username = config.get('username')
    password = config.get('password')

    if target == 'adguardhome':
        remote_path = config.get('adguardhome_config_path')
    else: # openwrt or mosdns
        remote_path = config.get(f"{target}_hosts_path")

    if not remote_path:
        error_msg = f"远程文件读取: 未在配置文件中找到 '{target}' 的远程路径。"
        logging.error(error_msg)
        return error_msg, False

    logging.info(f"远程文件读取: 准备连接到 {host}:{port} 读取 {remote_path}")

    try:
        with paramiko.SSHClient() as ssh_client:
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(hostname=host, port=port, username=username, password=password, timeout=10)

            with ssh_client.open_sftp() as sftp:
                logging.info(f"远程文件读取: 正在读取远程文件 {remote_path}")
                with sftp.open(remote_path, 'r') as remote_file:
                    content = remote_file.read().decode('utf-8')

                # 如果目标是 AdGuard Home，只提取 rewrites 部分
                if target == 'adguardhome':
                    try:
                        data = yaml.safe_load(content)
                        rewrites = data.get('filtering', {}).get('rewrites', [])
                        # 将 rewrites 部分格式化为 YAML 字符串以便在前端显示
                        # 如果 rewrites 为空或不存在，提供一个提示
                        if rewrites:
                            display_content = yaml.dump({'rewrites': rewrites}, sort_keys=False, allow_unicode=True, indent=2)
                        else:
                            display_content = "# 远程配置文件中未找到或 'rewrites' 部分为空。\n# 您可以在此添加，格式如下：\nrewrites:\n  - domain: my.domain.com\n    answer: 1.2.3.4"
                        logging.info(f"远程文件读取: 成功提取 AdGuard Home 的 rewrites 部分。")
                        return display_content, True
                    except yaml.YAMLError as e:
                        error_msg = f"远程文件读取: 解析 AdGuard Home YAML 文件失败: {e}"
                        logging.error(error_msg)
                        return error_msg, False
                else:
                    logging.info(f"远程文件读取: 成功读取文件 {remote_path}")
                    return content, True

    except FileNotFoundError:
        error_msg = f"远程文件读取: 远程文件 {remote_path} 不存在。"
        logging.warning(error_msg)
        return error_msg, False
    except paramiko.AuthenticationException:
        error_msg = "远程文件读取: SSH 认证失败，请检查用户名和密码。"
        logging.error(error_msg)
        return error_msg, False
    except Exception as e:
        error_msg = f"远程文件读取: 发生错误: {e}"
        logging.error(error_msg)
        return error_msg, False

def write_remote_file(config, target: str, content: str) -> tuple[str, bool]:
    """
    通过 SSH 连接到远程设备并写入指定文件的内容。
    返回 (消息, 是否成功) 的元组。
    """
    host = config.get('host')
    port = config.getint('port', fallback=22)
    username = config.get('username')
    password = config.get('password')

    if target == 'adguardhome':
        remote_path = config.get('adguardhome_config_path')
    else: # openwrt or mosdns
        remote_path = config.get(f"{target}_hosts_path")

    if not remote_path:
        error_msg = f"远程文件写入: 未在配置文件中找到 '{target}' 的远程路径。"
        logging.error(error_msg)
        return error_msg, False

    logging.info(f"远程文件写入: 准备连接到 {host}:{port} 写入 {remote_path}")

    try:
        with paramiko.SSHClient() as ssh_client:
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(hostname=host, port=port, username=username, password=password, timeout=10)

            final_content = content
            # 如果是 AdGuard Home，需要执行“读取-修改-写入”的原子操作
            if target == 'adguardhome':
                logging.info("远程文件写入 (AdGuard Home): 正在合并 rewrites...")
                with ssh_client.open_sftp() as sftp:
                    try:
                        # 1. 读取远程的完整文件
                        with sftp.open(remote_path, 'r') as remote_file:
                            full_content_str = remote_file.read().decode('utf-8')
                        full_data = yaml.safe_load(full_content_str)
                        if not isinstance(full_data, dict):
                            full_data = {} # 如果文件内容不是字典，则从头开始
                    except (FileNotFoundError, yaml.YAMLError):
                        # 如果文件不存在或格式错误，则创建一个新的字典
                        full_data = {}
                
                try:
                    # 2. 解析从前端发来的、只包含 rewrites 的 YAML 片段
                    new_rewrites_data = yaml.safe_load(content)
                    new_rewrites_list = new_rewrites_data.get('rewrites', [])
                    if not isinstance(new_rewrites_list, list):
                        raise yaml.YAMLError("'rewrites' 字段必须是一个列表。")
                except yaml.YAMLError as e:
                    error_msg = f"远程文件写入: 您提供的 rewrites 内容格式无效: {e}"
                    logging.error(error_msg)
                    return error_msg, False

                # 3. 将新的 rewrites 列表合并回完整的配置数据中
                filtering = full_data.setdefault('filtering', {})
                filtering['rewrites'] = new_rewrites_list

                # 4. 将完整的配置数据转换回 YAML 字符串
                final_content = yaml.dump(full_data, sort_keys=False, allow_unicode=True, indent=2)

            remote_tmp_path = f"/tmp/updater_tmp_manual_{os.path.basename(remote_path)}"
            logging.info(f"远程文件写入: 正在写入临时文件 {remote_tmp_path}")
            with ssh_client.open_sftp() as sftp:
                with sftp.open(remote_tmp_path, 'w') as remote_file:
                    remote_file.write(final_content)
            
            logging.info(f"远程文件写入: 正在移动临时文件以覆盖原文件")
            stdin, stdout, stderr = ssh_client.exec_command(f"mv -f {remote_tmp_path} {remote_path}")
            exit_status = stdout.channel.recv_exit_status()
            
            if exit_status == 0:
                success_msg = f"成功更新文件 {remote_path}。"
                logging.info(f"远程文件写入: {success_msg}")
                return success_msg, True
            else:
                error_msg = f"远程文件写入: 移动文件失败: {stderr.read().decode('utf-8').strip()}"
                logging.error(error_msg)
                return error_msg, False
    except Exception as e:
        error_msg = f"远程文件写入: 发生错误: {e}"
        logging.error(error_msg)
        return error_msg, False

def _process_adguard_content(content: str, new_ip: str) -> tuple[str, bool]:
    """
    处理 AdGuard Home 配置文件内容，仅替换已存在的 rewrites 列表中的 IP 地址。
    返回 (更新后的内容, 是否有变化)
    """
    try:
        data = yaml.safe_load(content)
        if not isinstance(data, dict):
            logging.error("AdGuard Home 更新: 配置文件不是一个有效的 YAML 字典。")
            return content, False
        
        # 使用 .get() 安全地获取嵌套的键，如果不存在则不作任何修改，避免向配置中添加新字段
        filtering = data.get('filtering')
        if not isinstance(filtering, dict):
            logging.info("AdGuard Home 更新: 未在配置文件中找到 'filtering' 部分，跳过更新。")
            return content, False

        rewrites = filtering.get('rewrites')
        if not isinstance(rewrites, list):
            logging.info(f"AdGuard Home 更新: 未在 'filtering' 部分中找到 'rewrites' 列表，跳过更新。")
            return content, False

        if not rewrites:
            logging.info("AdGuard Home 更新: 'rewrites' 列表为空，没有域名可以更新。请在 AdGuard Home 界面添加 DNS 重写规则。")
            return content, False

        has_changed = False
        for entry in rewrites:
            # 只更新包含 'domain' 和 'answer' 的字典条目
            if isinstance(entry, dict) and 'domain' in entry and 'answer' in entry:
                if entry.get('answer') != new_ip:
                    entry['answer'] = new_ip
                    has_changed = True
        
        if has_changed:
            logging.info(f"AdGuard Home 更新: 已将 {len(rewrites)} 条重写规则的 IP 地址更新为 {new_ip}")
            # 将更新后的数据转回 YAML 字符串。这会格式化文件，但能确保结构正确。
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
