__author__ = 'YaronA'
__version__ = '2.4_Nov.19.2020'

import json
import requests
import socket
import time
import logging
import logging.handlers
from ast import literal_eval

#from urlparse import urlparse
from urllib.parse import urlparse

from vdirect_client import rest_client
from base_monitor import BaseMonitor


class AppMonitor (BaseMonitor):
    def __init__(self, config, r_client):
        BaseMonitor.__init__(self, config, r_client)

        self.urls = json.loads(self.config.get(
            'app_monitor', 'APPS_URL_TO_MONITOR'))

        self.MONITOR_INTERVAL = int(self.config.get(
            'app_monitor', 'MONITOR_INTERVAL'))
        self.APP_MONITOR_REQUEST_TIMEOUT = int(self.config.get(
            'app_monitor', 'APP_MONITOR_REQUEST_TIMEOUT'))
        self.RETRIES = int(self.config.get('app_monitor', 'RETRIES'))
        self.RETRY_INTERVAL = int(self.config.get(
            'app_monitor', 'RETRY_INTERVAL'))
        self.VDIRECT_VIP_HC_TEMPLATE_NAME = self.config.get(
            'app_monitor', 'VDIRECT_VIP_HC_TEMPLATE_NAME')

    def do_monitor(self):
        logging.info("Starting Applications Health Checks every " +
                     repr(self.MONITOR_INTERVAL) + " seconds")
        ok = True
        while ok:
            time.sleep(self.MONITOR_INTERVAL)
            #counter = 0
            urlListLength = len(self.urls)
            unAvailableUrls = []
            for url in self.urls:
                if not self._is_app_available(url):

                    logging.warning("Application " + literal_eval(repr(url)) + " is not Available. Retrying " +
                                    repr(self.RETRIES) + " more times [" + repr(self.RETRY_INTERVAL) +
                                    " sec interval]")
                    retry = 0
                    while retry < self.RETRIES:
                        logging.debug("Doing retries for URL " + literal_eval(repr(url)) + ", retry count: " +
                                      str(retry) + " out of: " + repr(self.RETRY_INTERVAL))
                        time.sleep(self.RETRY_INTERVAL)
                        if self._is_app_available(url):
                            logging.info("Application " + literal_eval(repr(url)) +
                                         " became Available, stopping retries")
                            break
                        elif retry + 1 == self.RETRIES:
                            application_enabled = self._is_app_enabled(url)
                            if not application_enabled:
                                logging.warning("Application " + literal_eval(repr(url)) +
                                                " failing/disabled at Real Servers. Continue Monitoring.")
                            else:
                                logging.error(
                                    "Application " + literal_eval(repr(url)) + " is Down, after Retries.")
                                unAvailableUrls.append(url)                                
                        retry += 1

            if len(unAvailableUrls) > urlListLength / 2:
                if self.are_both_devices_available():
                    if not self.are_both_devices_waf_ui_available():
                        ok = False
                    else:
                        logging.warning(
                            "Applications: " + str(unAvailableUrls) +
                            " are not available. Fail over is not possible. Secondary vADC WAF UI is UP. Continue monitoring.")
                else:
                    logging.warning(
                        "Applications: " + str(unAvailableUrls) +
                        " are not available. Fail over is not possible. Secondary vADC Alteon UI is Down. Continue monitoring.")
            else:
                unAvailableUrls = []
        return

    def _is_app_available(self, url):
        try:
            r = requests.get(url, verify=False,
                             timeout=self.APP_MONITOR_REQUEST_TIMEOUT)
            logging.info("status code = " + str(r.status_code) + ", for application: " + str(url))
        except Exception:
            return False

        return True

    def _is_app_enabled(self, url):
        url_netloc = urlparse(url).netloc
        ip = socket.gethostbyname(url_netloc)
        protocol = urlparse(url).scheme
        port = 80 if protocol == "http" else 443

        data = {'devices': [{'type': self.ALTEON_DEVICE_TYPE, 'name': self.vadcs[0]},
                            {'type': self.ALTEON_DEVICE_TYPE, 'name': self.vadcs[1]}],
                'vipIp': ip, 'port': port}

        res = self.client.runnable.run(
            data, 'ConfigurationTemplate', self.VDIRECT_VIP_HC_TEMPLATE_NAME, 'run')

        success = res[rest_client.RESP_DATA]['success']
        if success:
            status = res[rest_client.RESP_DATA]['parameters']['status']
        else:
            status = False

        return status
