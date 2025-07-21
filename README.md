# Cloudflare IP 优选服务 (Docker 打包版)

[![Docker Pulls](https://img.shields.io/docker/pulls/l429609201/cloudflare-optimizer?style=flat-square&logo=docker)](https://hub.docker.com/r/l429609201/cloudflare-optimizer)

🌩 自动测试 Cloudflare CDN 延迟和速度，筛选出最适合当前网络环境的 IP，并提供 Web UI 和 API 接口进行管理。

---

## ✨ 功能特性

- **现代化 Web UI**: 提供美观、易用的网页界面，实时展示最优 IP、测试结果、运行日志，并可在线编辑配置文件。
- **定时自动优选**: 根据预设的 Cron 表达式，定时自动执行 IP 速度测试。
- **心跳健康检查**: 定期 Ping 当前最优 IP，如果发现不可用，会自动触发新一轮的优选，确保 IP 始终可用。
- **SSH 自动更新**: 支持通过 SSH 自动更新 OpenWRT 的 `hosts` 文件或 MosDNS 的自定义 hosts 规则。
- **RESTful API**: 提供完备的 API 接口，方便第三方应用集成和调用。
- **一键化部署**: 提供 Dockerfile 和 Docker Compose 文件，实现一键部署和运行。
- **可配置下载代理**: 支持配置代理服务器，解决在部分网络环境下无法访问 GitHub 下载优选工具的问题。

## 🚀 快速开始

### 使用 Docker Compose 运行

1.  在您的服务器上创建一个目录，例如 `cf-optimizer`。
2.  在该目录下创建一个 `docker-compose.yml` 文件，内容如下：

```yaml
version: '3.8'

services:
  cf-optimizer:
    image: l429609201/cloudflare-optimizer:latest
    container_name: cf-optimizer
    restart: always
    ports:
      # 将主机的 6788 端口映射到容器的 6788 端口
      # 如果端口冲突，可以修改左边的端口，例如 "8080:6788"
      - "6788:6788"
    volumes:
      # 将本地的 config 目录挂载到容器内，用于持久化配置和结果
      # 首次运行时，程序会自动在此目录生成默认的 config.ini 文件
      - ./config:/app/config
    environment:
      # 设置容器时区，以确保定时任务准确执行
      - TZ=Asia/Shanghai
      # 设置运行用户和用户组的ID，避免权限问题
      - PUID=1000
      - PGID=1000
```

3.  在 `docker-compose.yml` 所在目录执行以下命令启动服务：

```bash
docker-compose up -d
```

4.  服务启动后，访问 `http://<你的服务器IP>:6788` 即可打开 Web 管理界面。

## 🛠️ 配置说明

首次运行后，程序会在您挂载的 `config` 目录下生成 `config.ini` 文件。您可以在 Web 界面的“配置”卡片中直接修改并保存。

### OpenWRT / MosDNS 自动更新

1.  在 `config.ini` 的 `[OpenWRT]` 部分填入正确的 SSH 信息，并设置 `enabled = true`。
2.  登录您的 OpenWRT 或 MosDNS 设备，编辑对应的 hosts 文件 (`/etc/hosts` 或 `/etc/mosdns/rule/hosts.txt`)。
3.  在文件中添加标记，并在标记之间添加您需要优选 IP 的域名。程序会自动更新这些域名对应的 IP 地址。

**格式示例：**
```
##自动CF优选开始##
your.domain.com
another.domain.com
##自动CF优选结束##
```

---

## 📖 API 文档

### 获取最优 IP
- **URL**: `/api/best_ip`
- **Method**: `GET`
- **Success Response**: `{"best_ip": "172.67.7.111"}`
- **Error Response**: `{"error": "最优IP尚未确定"}`, `status: 404`

### 获取最近一次的完整测试结果
- **URL**: `/api/results`
- **Method**: `GET`
- **Success Response**: `[{"IP 地址": "...", "已发送": "...", ...}]`
- **Error Response**: `{"error": "尚未有优选结果"}`, `status: 404`

### 获取实时日志
- **URL**: `/api/logs`
- **Method**: `GET`
- **Success Response**: `["log line 1", "log line 2", ...]`

### 获取当前配置
- **URL**: `/api/config`
- **Method**: `GET`
- **Success Response**: `{"cfst": {"params": "..."}, "Scheduler": {...}}`

### 更新配置
- **URL**: `/api/config`
- **Method**: `POST`
- **Body**: `config.ini` 的完整文本内容。
- **Content-Type**: `text/plain`
- **Success Response**: `{"message": "配置已更新"}`, `status: 200`

### 手动触发一次优选任务
- **URL**: `/api/run_test`
- **Method**: `POST`
- **Success Response**: `{"message": "IP优选任务已启动"}`, `status: 202`
- **Error Response**: `{"message": "优选任务已在运行中，请稍后再试"}`, `status: 429`

---

## 🙏 特别感谢

- [Cloudflare IP优选](https://github.com/XIU2/CloudflareSpeedTest?tab=readme-ov-file)：本项目核心优选工具的来源。
- [Cloudflare IP优选插件](https://github.com/jxxghp/MoviePilot-Plugins/blob/main/plugins/cloudflarespeedtest)：参考自动下载优选工具的相关代码。


