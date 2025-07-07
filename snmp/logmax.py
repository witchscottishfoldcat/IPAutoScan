# /opt/network_monitor.py
# /opt/network_monitor.py
import time
import logging
from logging.handlers import SysLogHandler
from datetime import timedelta
from easysnmp import Session, EasySNMPError
from pythonping import ping

# @lianziyang 2025-4-27

# 配置日志（同时发送到日志服务器和控制台）
logger = logging.getLogger('NetworkMonitor')
logger.setLevel(logging.INFO)

syslog_handler = SysLogHandler(address=('172.16.1.2', 514))
syslog_handler.setFormatter(logging.Formatter('%(name)s: %(message)s'))

console_handler = logging.StreamHandler()
console_handler.setFormatter(
    logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
)

logger.addHandler(syslog_handler)
logger.addHandler(console_handler)

# 设备监控阈值配置
CONFIG = {
    'cpu_threshold': 85,
    'mem_threshold': 80,
}


def ticks_to_time(ticks):
    """将sysUptime的百分之一秒转换为可读时间"""
    try:
        seconds = int(ticks) // 100
        return str(timedelta(seconds=seconds))
    except Exception as e:
        logger.error(f"时间转换失败: {str(e)}")
        return ticks


def check_system_info(session, device_ip):
    """获取系统基础信息"""
    try:
        # 获取系统基础信息OID
        info_oids = {
            'sysDescr': '1.3.6.1.2.1.1.1.0',
            'sysUptime': '1.3.6.1.2.1.1.3.0',
            'sysContact': '1.3.6.1.2.1.1.4.0',
            'sysName': '1.3.6.1.2.1.1.5.0'
        }

        results = {}
        for name, oid in info_oids.items():
            try:
                result = session.get(oid)
                if name == 'sysUptime':
                    results[name] = ticks_to_time(result.value)
                else:
                    results[name] = result.value
            except EasySNMPError as e:
                logger.warning(f"{device_ip} {name} 获取失败: {str(e)}")
                results[name] = 'N/A'

        logger.info(f"\n{device_ip} 系统信息:")
        logger.info(f"• 设备名称: {results['sysName']}")
        logger.info(f"• 运行时间: {results['sysUptime']}")
        logger.info(f"• 系统描述: {results['sysDescr'][:50]}...")  # 截断长描述
        logger.info(f"• 联系人: {results['sysContact']}")

    except Exception as e:
        logger.error(f"{device_ip} 系统信息检测失败: {str(e)}")


def check_cpu(session, device_ip):
    """检测CPU使用率"""
    try:
        cpu_load = session.get('1.3.6.1.4.1.2011.6.3.4.1.2.0.0.0')
        cpu_value = int(cpu_load.value)
        logger.info(f"{device_ip} 当前CPU负载: {cpu_value}%")
        if cpu_value >= CONFIG['cpu_threshold']:
            logger.warning(f"{device_ip} CPU负载超过阈值 {CONFIG['cpu_threshold']}%")
    except EasySNMPError as e:
        logger.error(f"{device_ip} 无法获取CPU负载: {str(e)}")
def check_snmp(device_ip, community='Huawei@123'):  # 修正默认社区名拼写
    try:
        logger.info(f"开始SNMP检测设备: {device_ip}")
        session = Session(
            hostname=device_ip,
            community=community,
            version=2,
            timeout=5,
            retries=2
        )

        # 调用系统基础信息检测函数
        check_system_info(session, device_ip)

        # 系统名称和描述（已移至check_system_info中，此处可删除或保留）
        sys_descr = session.get('1.3.6.1.2.1.1.1.0')
        sys_name = session.get('1.3.6.1.2.1.1.5.0')
        logger.info(f"{device_ip} 系统名称: {sys_name.value}")
        logger.debug(f"{device_ip} 系统描述: {sys_descr.value}")

        # CPU检测
        check_cpu(session, device_ip)

    except Exception as e:
        logger.error(f"{device_ip} SNMP检测失败: {str(e)}")
        if "community" in str(e).lower() or "authorization" in str(e).lower():
            logger.warning(f"尝试备用社区名 Huawei@123")  # 修正拼写错误
            check_snmp(device_ip, community='Huawei@123')  # 使用正确社区名
    finally:
        logger.info(f"完成SNMP检测设备: {device_ip}")

def check_ping(target_ip):
    logger.info(f"开始PING检测设备: {target_ip}")
    try:
        # 增加详细调试信息
        logger.debug(f"尝试PING {target_ip}，使用参数：count=3, timeout=2s")
        response = ping(target_ip, count=3, timeout=2)
        logger.debug(f"PING响应对象: {response}")

        if not response.success():
            logger.critical(f"{target_ip} 网络不可达，丢包率100%")
        else:
            avg_latency = response.rtt_avg_ms
            logger.info(f"{target_ip} 平均延迟: {avg_latency}ms")  # 改为info级别
            if avg_latency > 100:
                logger.warning(f"{target_ip} 网络延迟过高: {avg_latency}ms")
    except PermissionError as pe:
        logger.error(f"{target_ip} PING检测失败：权限不足（请以root或sudo运行）")
    except Exception as e:
        logger.error(f"{target_ip} PING检测异常: {str(e)}", exc_info=True)  # 打印堆栈
    finally:
        logger.info(f"完成PING检测设备: {target_ip}")

if __name__ == "__main__":
    network_devices = [
        {'ip': '192.168.1.252', 'community': 'Huawei@123'},
        {'ip': '192.168.1.253', 'community': 'Huawei@123'},
        {'ip': '172.16.1.101', 'community': 'Huawei@123'},
        {'ip': '192.168.100.1', 'community': 'Huawei@123'},
        {'ip': '172.16.1.102', 'community': 'Huawei@123'},
        {'ip': '192.168.5.100', 'community': 'Huawei@123'},
        {'ip': '192.168.200.254', 'community': 'Huawei@123'},
        {'ip': '192.168.100.5', 'community': 'Huawei@123'}
    ]
    logger.info("====== 启动网络监控程序 ======")
    try:
        while True:
            logger.info("开始新一轮设备检测...")
            for device in network_devices:
                logger.info(f"正在检测设备: {device['ip']}")
                check_snmp(device['ip'], device['community'])
                check_ping(device['ip'])
                logger.info(f"设备检测完成: {device['ip']}\n{'-' * 40}")

            logger.info("本轮检测全部完成，等待下次执行...")
            time.sleep(300)  # 5分钟间隔

    except KeyboardInterrupt:
        logger.info("====== 用户中断，停止监控 ======")
    except Exception as e:
        logger.error(f"未捕获的异常: {str(e)}")
    finally:
        logger.info("====== 程序退出 ======")