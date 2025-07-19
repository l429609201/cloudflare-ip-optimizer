from flask import Flask, jsonify, current_app, render_template, request
from .optimizer import CloudflareOptimizer  # 确保使用相对导入
from .updater import read_remote_file
from .state import app_state
from apscheduler.triggers.cron import CronTrigger
import threading
import logging
import configparser

def create_app(optimizer: CloudflareOptimizer, template_folder: str, static_folder: str) -> Flask:
    """创建并配置 Flask 应用实例 (Application Factory)"""
    app = Flask(__name__, template_folder=template_folder, static_folder=static_folder)
    app.config['OPTIMIZER_INSTANCE'] = optimizer

    @app.route('/', methods=['GET'])
    def index():
        return render_template('index.html')

    @app.route('/api/best_ip', methods=['GET'])
    def get_best_ip():
        if app_state.best_ip:
            return jsonify({"best_ip": app_state.best_ip})
        return jsonify({"error": "最优IP尚未确定"}), 404

    @app.route('/api/results', methods=['GET'])
    def get_results():
        if app_state.last_results:
            # 仅返回前10条结果给前端，减轻前端渲染压力
            return jsonify(app_state.last_results[:10])
        # 如果没有结果，返回空列表，前端会显示“暂无结果”
        return jsonify([])

    @app.route('/api/run_test', methods=['POST'])
    def run_test_manual():
        # 从 app.config 获取 optimizer 实例
        optimizer_instance: CloudflareOptimizer = app.config['OPTIMIZER_INSTANCE']
        # 在后台线程中运行，避免阻塞API请求
        if not app_state.optimizer_lock.locked():
            thread = threading.Thread(target=optimizer_instance.run_speed_test)
            thread.start()
            return jsonify({"message": "IP优选任务已启动"}), 202
        else:
            return jsonify({"message": "优选任务已在运行中，请稍后再试"}), 429

    @app.route('/api/config', methods=['GET'])
    def get_config():
        # 直接读取并返回配置文件的原始文本内容，以保留顺序和注释
        config_file_path = current_app.config['CONFIG_FILE_PATH']
        try:
            with open(config_file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            return content, 200, {'Content-Type': 'text/plain; charset=utf-8'}
        except Exception as e:
            logging.error(f"读取配置文件时出错: {e}")
            return jsonify({"error": f"读取配置文件时出错: {e}"}), 500

    @app.route('/api/logs', methods=['GET'])
    def get_logs():
        # 读取日志文件内容并返回
        log_file_path = current_app.config['LOG_FILE_PATH']
        try:
            with open(log_file_path, 'r', encoding='utf-8') as f:
                logs = f.readlines()
            return jsonify(logs)
        except FileNotFoundError:
            logging.warning(f"日志文件未找到: {log_file_path}")
            return jsonify({"error": "日志文件未找到"}), 404

    @app.route('/api/remote_file', methods=['GET'])
    def get_remote_file():
        target = request.args.get('target')
        if not target or target not in ['openwrt', 'mosdns', 'adguardhome']:
            return "必须提供有效的 target 参数 (openwrt, mosdns, adguardhome)", 400, {'Content-Type': 'text/plain; charset=utf-8'}

        openwrt_config = current_app.config['CONFIG']['OpenWRT']
        if not openwrt_config.getboolean('enabled'):
            return "SSH 功能未在 config.ini 中启用", 403, {'Content-Type': 'text/plain; charset=utf-8'}

        content, success = read_remote_file(openwrt_config, target)

        if success:
            return content, 200, {'Content-Type': 'text/plain; charset=utf-8'}
        else:
            # content is the error message
            return content, 500, {'Content-Type': 'text/plain; charset=utf-8'}

    @app.route('/api/config', methods=['POST'])  # 修改为 POST 方法
    def update_config():
        config_file_path = current_app.config['CONFIG_FILE_PATH']
        try:
            # 直接获取文本内容
            new_config = request.get_data(as_text=True)

            # 写入文件
            with open(config_file_path, 'w', encoding='utf-8') as f:
                f.write(new_config)
            
            logging.info("配置文件已保存，正在热重载应用配置...")

            # 1. 重新加载配置到内存中的 config 对象
            config = current_app.config['CONFIG']
            config.read(config_file_path, encoding='utf-8')

            # 2. 通知 Optimizer 实例重载其内部配置
            optimizer_instance = current_app.config.get('OPTIMIZER_INSTANCE')
            if optimizer_instance:
                optimizer_instance.reload_config()

            # 3. 重新加载并应用定时任务
            scheduler = current_app.config.get('SCHEDULER')
            if scheduler:
                new_optimize_cron = config.get('Scheduler', 'optimize_cron', fallback='0 3 * * *')
                new_heartbeat_cron = config.get('Scheduler', 'heartbeat_cron', fallback='*/5 * * * *')

                scheduler.reschedule_job('job_optimize_ip', trigger=CronTrigger.from_crontab(new_optimize_cron))
                scheduler.reschedule_job('job_heartbeat_check', trigger=CronTrigger.from_crontab(new_heartbeat_cron))
                
                logging.info(f"定时优选任务已更新，新 Cron: {new_optimize_cron}")
                logging.info(f"心跳检测任务已更新，新 Cron: {new_heartbeat_cron}")

            return jsonify({"message": "配置已更新并成功热重载！"}), 200
        except Exception as e:
            logging.error(f"更新配置时失败: {e}")
            return jsonify({"error": f"更新配置时失败: {e}"}), 500
    return app
