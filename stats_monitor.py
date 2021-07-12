__author__ = 'YaronA'
__version__ = '2.4_Nov.19.2020'

import copy
import json
import requests
import time
import logging
import logging.handlers

from base_monitor import BaseMonitor
from requests.auth import HTTPBasicAuth


class StatsMonitor (BaseMonitor):
    def __init__(self, config, r_client):
        BaseMonitor.__init__(self, config, r_client)

        self.thresholds = {'aw_ResourceAppServerMem': int(self.config.get('stats_monitor',
                                                                          'REBOOT_MEMORY_PERCENTAGE_THRESHOLD')),
                           'aw_ResourceAppServerCPU': int(self.config.get('stats_monitor',
                                                                          'REBOOT_CPU_PERCENTAGE_THRESHOLD')),
                           'Active Connections': int(self.config.get('stats_monitor',
                                                                     'REBOOT_ACTIVE_CONNECTIONS_THRESHOLD')),
                           'Connections Rate': int(self.config.get('stats_monitor',
                                                                   'REBOOT_CONNECTION_RATE_THRESHOLD')),
                           'Transactions Rate': int(self.config.get('stats_monitor',
                                                                    'REBOOT_TRANSACTIONS_RATE_THRESHOLD'))}

        self.STATS_MONITOR_RETRY_INTERVAL = int(self.config.get('stats_monitor', 'STATS_MONITOR_RETRY_INTERVAL'))

        self.STATS_MONITOR_REQUEST_TIMEOUT = int(self.config.get('stats_monitor', 'STATS_MONITOR_REQUEST_TIMEOUT'))
        self.STATS_MONITOR_REQUEST_RETRIES = int(self.config.get('stats_monitor', 'STATS_MONITOR_REQUEST_RETRIES'))
        self.MONITOR_INTERVAL = int(self.config.get('stats_monitor', 'MONITOR_INTERVAL'))

        self.RESOURCE_URL = self.config.get('stats_monitor', 'RESOURCE_URL')
        self.COUNTERS_URL = self.config.get('stats_monitor', 'COUNTERS_URL')

        self.PRIMARY_CONTAINER_NAME = self.config.get('stats_monitor', 'ALTEON_PRIMARY_CONTAINER_NAME')
        self.SECONDARY_CONTAINER_NAME = self.config.get('stats_monitor', 'ALTEON_SECONDARY_CONTAINER_NAME')

    def do_monitor(self):

        logging.info("Starting vADC Statistics check every " + repr(self.MONITOR_INTERVAL) + " seconds")
        while True:
            time.sleep(self.MONITOR_INTERVAL)

            if not self.are_both_devices_available():
                logging.warning("Skipping Statistics sampling since no Master device can be determined.")
                continue
            master_device_ip = self.log_device_ip_to_reboot()
            stats_json = self.get_statistics(master_device_ip)
            if stats_json:
                if not self._check_stats_thresholds(stats_json, master_device_ip):
                    break

    def get_statistics(self, master_device_ip):
        res_p_r = self._do_get_perf('https://' + master_device_ip + "/" + self.RESOURCE_URL)
        res_p_c = self._do_get_perf('https://' + master_device_ip + "/" + self.COUNTERS_URL)

        if not res_p_r or not res_p_c:
            logging.warning("Device " + self.name_dict.get(master_device_ip) + " failed RestAPI Query.")
            return None
        else:
            res_p_r = json.loads(res_p_r.content)
            res_p_c = json.loads(res_p_c.content)
            stats_json = self._aw_stats_collect(res_p_r, res_p_c)

        return stats_json

    def _check_stats_thresholds(self, stats_json, master_device_ip):

        def _check_threshold_breached(value, threshold):
            return threshold != 0 and value >= threshold

        keys = copy.deepcopy(stats_json.keys())
        for key in keys:
            retry = 0
            while retry < 3:
                if not _check_threshold_breached(stats_json[key], self.thresholds[key]):
                    if retry > 0:
                        logging.info(key + "'s value (" + str(stats_json[key]) + ") is below the threshold (" +
                                     str(self.thresholds[key]) + ") on device " + self.name_dict.get(master_device_ip))
                    break
                else:
                    retry += 1
                    if retry == 3:
                        logging.error(key + "'s value (" + str(stats_json[key]) + ") is above the threshold (" +
                                      str(self.thresholds[key]) + ") on device " + self.name_dict.get(
                            master_device_ip) +
                                      " for " + str(
                            self.STATS_MONITOR_RETRY_INTERVAL * 3) + " seconds . Rebooting device.")
                        return False
                    logging.warning(key + "'s value (" + str(stats_json[key]) + ") is above the threshold (" +
                                    str(self.thresholds[key]) + ") on device " + self.name_dict.get(master_device_ip) +
                                    ". Going to retry in " + str(self.STATS_MONITOR_RETRY_INTERVAL) + " seconds.")
                    time.sleep(self.STATS_MONITOR_RETRY_INTERVAL)
                    stats_json = self.get_statistics(master_device_ip)
                    if not stats_json:
                        break
        return True

    def _aw_stats_collect(self, res_p_r, res_p_c):
        stats_json = {'aw_ResourceAppServerMem': int(float(res_p_r['ResourceAppServerMem'][:-1])),
                'aw_ResourceAppServerCPU': int(float(res_p_r['ResourceAppServerCPU'][:-1]))}
        fields_to_collect = ['Active Connections', 'Connections Rate', 'Transactions Rate']
        for counter in res_p_c['AppwallActivityCount']:
            if counter['Activity'] in fields_to_collect:
                stats_json[counter['Activity']] = int(counter['Current'])

        return stats_json

    def _do_get_perf(self, url):
        try:
            retry = 0
            while retry < self.STATS_MONITOR_REQUEST_RETRIES:
                res = requests.get(url, auth=HTTPBasicAuth(self.ALTEON_USERNAME, self.ALTEON_PASSWORD),
                                   verify=False, timeout=self.STATS_MONITOR_REQUEST_TIMEOUT)
                if res.status_code != 200:
                    retry += 1
                    if retry == 3:
                        return False
                    time.sleep(self.STATS_MONITOR_RETRY_INTERVAL)
                else:
                    return res
        except Exception:
            return False
