__author__ = 'YaronA'
__version__ = '2.4_Nov.19.2020'

import abc
import requests
import time
import logging
import logging.handlers
from ast import literal_eval
from requests.auth import HTTPBasicAuth
from vdirect_client import rest_client

class BaseMonitor ():
    def __init__(self, config, r_client):

        self.config = config
        self.client = r_client

        self.PRIMARY_IP = self.config.get('general', 'ALTEON_PRIMARY_IP')
        self.SECONDARY_IP = self.config.get('general', 'ALTEON_SECONDARY_IP')

        self.vadcs = [self.PRIMARY_IP, self.SECONDARY_IP]

        self.ALTEON_USERNAME = self.config.get('general', 'ALTEON_USERNAME')
        self.ALTEON_PASSWORD = self.config.get('general', 'ALTEON_PASSWORD')
        self.ALTEON_DEVICE_TYPE = self.config.get('general', 'ALTEON_DEVICE_TYPE')
        self.VDIRECT_TECHDATA_TEMPLATE_NAME = self.config.get('general', 'VDIRECT_TECHDATA_TEMPLATE_NAME')
        self.TECHDATA_SERVER_IP = self.config.get('general', 'TECHDATA_SERVER_IP')
        self.TECHDATA_SERVER_USERNAME = self.config.get('general', 'TECHDATA_SERVER_USERNAME')
        self.TECHDATA_SERVER_PASSWORD = self.config.get('general', 'TECHDATA_SERVER_PASSWORD')
        self.TECHDATA_FOLDER_NAME = self.config.get('general', 'TECHDATA_FOLDER_NAME')

        self.DEVICE_REQUEST_TIMEOUT = int(self.config.get('general', 'DEVICE_REQUEST_TIMEOUT'))
        self.DEVICE_AVAILABILITY_URL = self.config.get('general', 'DEVICE_AVAILABILITY_URL')
        self.DEVICE_WAF_AVAILABILITY_URL = self.config.get('general', 'DEVICE_WAF_AVAILABILITY_URL')
        self.DEVICE_AVAILABILITY_TIMEOUT = int(self.config.get('general', 'DEVICE_AVAILABILITY_TIMEOUT'))

        self.FAIL_OVER_WAIT = int(self.config.get('general', 'FAIL_OVER_WAIT'))
        self.FAIL_OVER_INTERVAL = int(self.config.get('general', 'FAIL_OVER_INTERVAL'))
        self.FAILOVER_SAFE_PERIOD = int(config.get('general', 'FAILOVER_SAFE_PERIOD'))


        self.VDIRECT_FAILOVER_TEMPLATE_NAME = self.config.get('general', 'VDIRECT_FAILOVER_TEMPLATE_NAME')
        self.VDIRECT_GET_MASTER_TEMPLATE_NAME = self.config.get('general', 'VDIRECT_GET_MASTER_TEMPLATE_NAME')
        self.VDIRECT_REBOOT_TEMPLATE_NAME = self.config.get('general', 'VDIRECT_REBOOT_TEMPLATE_NAME')

        self.RETRIES = int(self.config.get('app_monitor', 'RETRIES'))
        self.RETRY_INTERVAL = int(self.config.get('app_monitor', 'RETRY_INTERVAL'))


        primary_sys_name = self._get_sys_names(self.PRIMARY_IP)
        secondary_sys_name = self._get_sys_names(self.SECONDARY_IP)

        self.name_dict = {self.PRIMARY_IP: primary_sys_name, self.SECONDARY_IP: secondary_sys_name}

    def _get_sys_names(self, ip_address):
        try:
            retry = 0
            while retry < self.RETRIES:
                r_p = requests.get('https://' + ip_address + '/config?prop=sysName',
                                   auth=HTTPBasicAuth(self.ALTEON_USERNAME, self.ALTEON_PASSWORD),
                                   verify=False, timeout=self.DEVICE_REQUEST_TIMEOUT)
                if r_p.status_code != 200:
                    retry += 1
                elif r_p.json()['sysName'] != "":
                    sys_name = r_p.json()['sysName']
                    return sys_name
                elif r_p.json()['sysName'] == "":
                    logging.error("No sysname is configuered for device " + literal_eval(repr(ip_address))
                                  + " setting the IP as name")
                    return ip_address
                if retry ==3:
                    logging.error("Failed to get sysname for device " + literal_eval(repr(ip_address)) +
                                  " setting the IP as name")
                    return ip_address
        except Exception as ex:
            # logging.error("Caught " + repr(ex.__class__) + ". Message: " + repr(ex.message))
            logging.error("Caught " + repr(ex.__class__) + ". Message: " + repr(ex))
            logging.error("Failed to get sysname for device " + literal_eval(repr(ip_address)) +
                          " setting the IP as name")
        except RuntimeError as er:
            # logging.error("Caught " + repr(er.__class__) + ". Message: " + repr(er.message))
            logging.error("Caught " + repr(er.__class__) + ". Message: " + repr(er))
            logging.error("Failed to get sysname for device " + literal_eval(repr(ip_address)) +
                          " setting the IP as name")
        return ip_address

    @abc.abstractmethod
    def do_monitor(self):
        return

    def log_device_ip_to_reboot(self):
        data = {'devices': [{'type': self.ALTEON_DEVICE_TYPE, 'name': self.vadcs[0]},
                            {'type': self.ALTEON_DEVICE_TYPE, 'name': self.vadcs[1]}]}
        res = self.client.runnable.run(data, 'ConfigurationTemplate', self.VDIRECT_GET_MASTER_TEMPLATE_NAME, 'run')

        success = res[rest_client.RESP_DATA]['success']
        if success:
            return res[rest_client.RESP_DATA]['parameters']['masterIp']

        logging.error("Failed to get the ADC service master device.")
        return None

    def fail_over(self, master_device_ip):

        logging.info("Performing failover on vADC " +
                     self.name_dict.get(master_device_ip) + ".Moving to Backup.")
        data = {'devices': [{'type': self.ALTEON_DEVICE_TYPE, 'name': self.vadcs[0]},
                            {'type': self.ALTEON_DEVICE_TYPE, 'name': self.vadcs[1]}]}
        res = self.client.runnable.run(data, 'ConfigurationTemplate', self.VDIRECT_FAILOVER_TEMPLATE_NAME, 'run')

        return res[rest_client.RESP_DATA]['success']

    def reboot(self, master_device_ip):
        logging.error("Rebooting " + self.name_dict.get(master_device_ip) + " vADC device")
        data = {'adc': {'type': self.ALTEON_DEVICE_TYPE, 'name': master_device_ip}}
        self.client.runnable.run(data, 'ConfigurationTemplate', self.VDIRECT_REBOOT_TEMPLATE_NAME, 'run')

    def dump_tech_data(self, master_device_ip):
        logging.info("Collecting TechData from vADC " + self.name_dict.get(literal_eval(repr(master_device_ip))) +
                     ". It might take few minutes.")
        data = {'devices': [{'type': self.ALTEON_DEVICE_TYPE, 'name': master_device_ip}],
                'serverIP': self.TECHDATA_SERVER_IP, 'username': self.TECHDATA_SERVER_USERNAME,
                'password': self.TECHDATA_SERVER_PASSWORD, 'foldername': self.TECHDATA_FOLDER_NAME}
        res = self.client.runnable.run(data, 'ConfigurationTemplate', self.VDIRECT_TECHDATA_TEMPLATE_NAME, 'run')
        success = res[rest_client.RESP_DATA]['success']
        if success:
            logging.info("Tech-data exported from vADC " + self.name_dict.get(literal_eval(repr(master_device_ip))))
        else:
            logging.info("Tech-data Failed to Export from vADC " +
                         self.name_dict.get(literal_eval(repr(master_device_ip))))

    def are_both_devices_available(self):
        return self.is_devices_available(self.PRIMARY_IP) and self.is_devices_available(self.SECONDARY_IP)

    def is_devices_available(self, device_ip):
        try:
            resp = requests.get('https://' + device_ip + "/" + self.DEVICE_AVAILABILITY_URL,
                                auth=HTTPBasicAuth(self.ALTEON_USERNAME, self.ALTEON_PASSWORD),
                                verify=False, timeout=self.DEVICE_AVAILABILITY_TIMEOUT)
            if resp.status_code != 200:
                return False
        except Exception as e:
            # logging.warning("Failed to check device " + repr(device_ip) + " availability: EXCEPTION:" + repr(e.message))
            logging.warning("Failed to check device " + repr(device_ip) + " availability: EXCEPTION:" + repr(e))
            return False
        return True

    def are_both_devices_waf_ui_available(self):
        return self.is_devices_waf_ui_available(self.PRIMARY_IP) and self.is_devices_waf_ui_available(self.SECONDARY_IP)

    def is_devices_waf_ui_available(self, device_ip):
        try:
            resp = requests.get('https://' + device_ip + "/" + self.DEVICE_WAF_AVAILABILITY_URL,
                                auth=HTTPBasicAuth(self.ALTEON_USERNAME, self.ALTEON_PASSWORD),
                                verify=False, timeout=self.DEVICE_AVAILABILITY_TIMEOUT)
            if resp.status_code != 200:
                return False
        except Exception as e:
            # logging.warning("Failed to check device " + repr(device_ip) + " availability: EXCEPTION:" + repr(e.message))
            logging.warning("Failed to check device WAF UI " + repr(device_ip) + " availability: EXCEPTION:" + repr(e))
            return False
        return True
