__author__ = 'YaronA'
__version__ = '2.4_Nov.19.2020'

#import ConfigParser
import configparser
import os
import requests
import ssl
import socket
import sys
import time
import logging
import logging.handlers

from app_monitor_v2 import AppMonitor
from stats_monitor import StatsMonitor

from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.packages.urllib3.exceptions import InsecurePlatformWarning
from threading import Thread

try:
    from vdirect_client import rest_client
    HAS_REST_CLIENT = True
except ImportError:
    HAS_REST_CLIENT = False


LAST_FAIL_OVER_TIMESTAMP = 0


def log_setup(log_path, syslog_ip, syslog_port):
    log_dir_name = log_path + '/log/'
    if not os.path.exists(log_dir_name):
        os.makedirs(log_dir_name)

    log_handler = logging.handlers.RotatingFileHandler(log_dir_name + "monitor.txt", maxBytes=20960000, backupCount=5)
    syslog_handler = logging.handlers.SysLogHandler(address=(syslog_ip, syslog_port),
                                                    facility=logging.handlers.SysLogHandler.LOG_USER,
                                                    socktype=socket.SOCK_DGRAM)
    log_formatter = logging.Formatter(
        '%(asctime)s AW monitoring: %(message)s',
        '%b %d %H:%M:%S')
    syslog_formatter = logging.Formatter(
        '%(asctime)s Radware AW monitoring: %(message)s',
        '%b %d %H:%M:%S')

    log_handler.setFormatter(log_formatter)
    syslog_handler.setFormatter(syslog_formatter)
    logger = logging.getLogger()
    logger.addHandler(log_handler)
    logger.addHandler(syslog_handler)
    logger.setLevel(logging.INFO)


def monitor_func(monitor):
    try:
        while True:
            monitor.do_monitor()

            fail_over_thread = Thread(target=fail_over_func, args=(monitor,))
            fail_over_thread.start()

    # except Exception as ex:
    #     logging.error("Monitor caught " + repr(ex.__class__) + ". Message: " + repr(ex.message) +
    #                   ". Monitoring stopped.")
    # except RuntimeError as er:
    #     logging.error("Monitor caught " + repr(er.__class__) + ". Message: " + repr(er.message) +
    #                   ". Monitoring stopped.")
    except Exception as ex:
        logging.error("Monitor caught " + repr(ex.__class__) + ". Message: " + repr(ex
        ) +
                      ". Monitoring stopped.")
    except RuntimeError as er:
        logging.error("Monitor caught " + repr(er.__class__) + ". Message: " + repr(er) +
                      ". Monitoring stopped.")


def fail_over_func(monitor):
    global LAST_FAIL_OVER_TIMESTAMP
    if LAST_FAIL_OVER_TIMESTAMP + monitor.FAILOVER_SAFE_PERIOD > time.time():
        logging.warning("No Failover process will be performed. Last Failover was performed less than " +
                         repr(monitor.FAILOVER_SAFE_PERIOD) + " seconds ago")
        return
    LAST_FAIL_OVER_TIMESTAMP = time.time()

    try:
        logging.info("Starting Failover process.")
        master_device_ip = monitor.log_device_ip_to_reboot()
        fail_over_success = monitor.fail_over(master_device_ip)
        if fail_over_success:
            logging.info("Failover Completed.")
            monitor.dump_tech_data(master_device_ip)
        else:
            logging.warning("Failed to Failover the service. Techdata will not be collected.")

        monitor.reboot(master_device_ip)

    # except Exception as ex:
    #     logging.error("Failed to failover the service. Exception caught:" + repr(ex.__class__) +
    #                   ". Message: " + repr(ex.message))
    # except RuntimeError as er:
    #     logging.error("Failed to failover the service. Runtime error occurred:" + repr(er.__class__) +
    #                   ". Message: " + repr(er.message))
    except Exception as ex:
        logging.error("Failed to failover the service. Exception caught:" + repr(ex.__class__) +
                      ". Message: " + repr(ex))
    except RuntimeError as er:
        logging.error("Failed to failover the service. Runtime error occurred:" + repr(er.__class__) +
                      ". Message: " + repr(er))

def set_exit_handler(func):
    import signal
    signal.signal(signal.SIGTERM, func)


def on_exit():
    logging.error("Application Monitor Python Script Stopped, Halted or Crashed.")
    sys.exit(0)


def main():

    logging.getLogger("requests").setLevel(logging.ERROR)

    if not HAS_REST_CLIENT:
        raise ImportError("The vdirect-client package is required.")

    path = os.path.abspath(__file__)
    dir_path = os.path.dirname(path)
    os.chdir(dir_path)

    #config = ConfigParser.ConfigParser()
    config = configparser.ConfigParser()
    config.read('monitor.ini')

    try:
        _create_unverified_https_context = ssl._create_unverified_context
    except AttributeError:
        pass
    else:
        ssl._create_default_https_context = _create_unverified_https_context

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)

    vdirect_ip = config.get('general', 'VDIRECT_IP')
    vdirect_username = config.get('general', 'VDIRECT_USERNAME')
    vdirect_password = config.get('general', 'VDIRECT_PASSWORD')

    syslog_ip = config.get('general', 'SYSLOG_SERVER_IP')
    syslog_port = int(config.get('general', 'SYSLOG_UDP_PORT'))

    r_client = rest_client.RestClient(
        vdirect_ip,
        vdirect_username,
        vdirect_password,
        timeout=180,
        verify=False)

    log_setup(dir_path, syslog_ip, syslog_port)
    set_exit_handler(on_exit)

    app_monitor = AppMonitor(config, r_client)
    app_monitor_thread = Thread(target=monitor_func, args=(app_monitor,))
    app_monitor_thread.start()

    #stats_monitor = StatsMonitor(config, r_client)
    #stats_monitor_thread = Thread(target=monitor_func, args=(stats_monitor,))
    #stats_monitor_thread.start()

    app_monitor_thread.join()
    #stats_monitor_thread.join()
    logging.info("Monitoring Stopped.")

if __name__ == "__main__":
    main()
