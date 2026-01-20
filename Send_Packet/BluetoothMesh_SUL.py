import logging
import os
import sys
import time
import subprocess
import signal

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/../../")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/../libs/")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/../libs/boofuzz/")
from colorama import Fore
import random
from time import sleep
from aalpy.base import SUL
# 必须先导入 ble_mesh 以应用 summary 方法的补丁
from scapy.contrib import ble_mesh
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
import Transfer.Send_Packet.constant as constant
from Transfer.Send_Packet.Packet_Constuction import Packet_Constuction
# from Transfer.Fail_Exception.Fail_Exception import *
import configparser
from Transfer.Send_Packet.Out_map import get_map
from scapy.utils import hexdump
import json

Layers = {0: "adv_pkts", 1: "ll_pkts", 2: "l2cap_pkts", 3: "smp_pkts", 4: "att_pkts"}


class InterruptHandler:
    """处理程序中断的辅助类"""

    def __init__(self):
        self.interrupted = False
        # 注册信号处理器
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, signum, frame):
        # print(f"\n{Fore.YELLOW}收到中断信号 {signum}，正在优雅退出...")
        self.interrupted = True

    def check_interrupt(self):
        return self.interrupted


class BluetoothMesh_SUL(SUL):
    def __init__(self, driver, unprovisioned_device_address, iat, rat, role, rx_len, tx_len, logger_handle,
                 key_path=None, packet_layer=None, return_handle_layer=[], send_handle_layer=[], device_name=None,
                 presponse=False, algorithm=1):
        super().__init__()
        self.unprovisioned_device_address = unprovisioned_device_address
        self.rx_len = rx_len
        self.tx_len = tx_len
        self.key_path = key_path
        self.provisioned = False
        self.algorithm = algorithm
        # self.data_prepare()
        self.iat = iat
        self.rat = rat
        self.role = role
        self.slave_addr_type = None
        self.driver = driver
        self.logger_handle = logger_handle
        self.logger = logging.getLogger(logger_handle)

        self.interrupt_handler = InterruptHandler()
        self.connection_error_counter = 0
        self.packet_layer = packet_layer
        self.return_handle_layer = return_handle_layer
        self.send_handle_layer = send_handle_layer
        # self.logger.info("Advertiser Address: " + self.advertiser_address)
        self.exit_flag = False
        self.config = configparser.ConfigParser()
        self.deviceuuid = None
        self.print_show = False
        self.advertiser_address = None
        self.pairing_times = 0
        self.device_name = device_name
        self.device_found = False
        self.start_time = time.time()
        self.presponse = presponse


        # self.data_prepare()
        
    def data_prepare(self):
        rand_hex_str = hex(random.getrandbits(48))[2:].zfill(12)
        if self.provisioned:
            with open(self.key_path, 'r') as f:
                data = json.load(f)
                self.advertiser_address = data['AdvA']
        else:
            self.advertiser_address = ':'.join(a + b for a, b in zip(rand_hex_str[::2], rand_hex_str[1::2]))  # generate random link idLink ID 应当是均匀随机的无符号 32 位整数
        self.link_id = random.getrandbits(32)
        self.packet_construction = Packet_Constuction(self.link_id, self.advertiser_address, self.rx_len, self.tx_len,
                                                      self.key_path, self.provisioned)

        self.packet_construction.kdf.set_algorithm(self.algorithm)
        self.packet_construction.pbadv_handle.set_device_uuid(self.deviceuuid)
        self.packet_construction.pbadv_handle.algorithm = self.algorithm
        self.pbadvpkts = ["pbadv_pkts", 'link_open_message_pkt', 'link_ack_message_pkt', 'link_close_message_pkt',
                          'provisioning_invite_pkt', 'provisioning_capability_pkt', 'provisioning_start_pkt',
                          'provisioning_public_key_pkt', 'provisioning_confirmation_pkt', 'provisioning_random_pkt',
                          'provisioning_data_pkt', 'provisioning_complete_pkt', 'provisioning_failed_pkt',
                          'transaction_acknowledgment_pkt']
        self.beaconpkts = ["beacon_pkts", 'unprovisioned_device_beacon_pkt', 'secure_network_beacon_pkt',
                           'mesh_private_beacon_pkt']
        self.messagepkts = ["message_pkts", 'config_beacon_get_pkt', 'config_beacon_set_pkt',
                            'config_beacon_status_pkt', 'config_composition_data_get_pkt', 'config_default_ttl_get_pkt',
                            'config_default_ttl_set_pkt', 'config_default_ttl_status_pkt', 'config_gatt_proxy_get_pkt',
                            'config_gatt_proxy_set_pkt', 'config_gatt_proxy_status_pkt',
                            'config_relay_get_pkt', 'config_relay_set_pkt', 'config_relay_status_pkt',
                            'config_model_publication_get_pkt', 'config_model_publication_set_pkt',
                            'config_model_publication_virtual_address_set_pkt', 'config_model_publication_status_pkt',
                            'config_model_subscription_add_pkt', 'config_model_subscription_virtual_address_add_pkt',
                            'config_model_subscription_delete_pkt',
                            'config_model_subscription_virtual_address_delete_pkt',
                            'config_model_subscription_status_pkt', 'config_sig_model_subscription_get_pkt',
                            'config_sig_model_subscription_get_pkt', 'config_sig_model_subscription_list_pkt',
                            'config_vendor_model_subscription_get_pkt', 'config_vendor_model_subscription_list_pkt',
                            'config_netkey_add_pkt', 'config_netkey_update_pkt', 'config_netkey_delete_pkt',
                            'config_netkey_status_pkt', 'config_netkey_get_pkt', 'config_netkey_list_pkt',
                            'config_app_key_add_pkt', 'config_app_key_update_pkt', 'config_app_key_delete_pkt',
                            'config_app_key_status_pkt', 'config_app_key_get_pkt', 'config_app_key_list_pkt',
                            'config_node_identity_get_pkt', 'config_node_identity_set_pkt',
                            'config_node_identity_status_pkt', 'config_model_app_bind_pkt',
                            'config_model_app_unbind_pkt', 'config_model_app_status_pkt',
                            'config_sig_model_app_get_pkt', 'config_sig_model_app_list_pkt',
                            'config_vendor_model_app_get_pkt', 'config_vendor_model_app_list_pkt',
                            'config_node_reset_pkt', 'config_node_reset_status_pkt', 'config_friend_get_pkt',
                            'config_friend_set_pkt', 'config_friend_status_pkt', 'config_key_refresh_phase_get_pkt',
                            'config_key_refresh_phase_set_pkt', 'config_key_refresh_phase_status_pkt',
                            'config_heartbeat_publication_get_pkt', 'config_heartbeat_publication_set_pkt',
                            'config_heartbeat_publication_status_pkt', 'config_heartbeat_subscription_get_pkt',
                            'config_heartbeat_subscription_set_pkt',
                            'config_heartbeat_subscription_status_pkt', 'config_low_power_node_poll_timeout_get_pkt',
                            'config_low_power_node_poll_timeout_status_pkt', 'config_network_transmit_get_pkt',
                            'config_network_transmit_set_pkt', 'config_network_transmit_status_pkt', 'segment_ack_pkt','generic_onoff_get_pkt']

        self.packet_construction.get_pkts(self.pbadvpkts)
        self.packet_construction.get_pkts(self.beaconpkts)
        self.packet_construction.get_pkts(self.messagepkts)

    def packet_send_received_control(self, send_pkt, send_attempts=constant.NORMAL_SEND_ATTEMPTS,
                                     receive_attempts=constant.NORMAL_RECEIVE_ATTEMPTS, repeat=None, log=False):
        received = []
        result = set()
        return_list = []
        # self.logger.info('Input words: {} '.format(send_pkt.summary()))
        # if (("ll_pkts" in self.send_handle_layer) and send_pkt.haslayer('BTLE_CTRL')) or (("smp_pkts" in self.send_handle_layer) and send_pkt.haslayer('SM_Hdr')):
        # send_pkt = self.packet_construction.encryption_check(send_pkt)
        if isinstance(send_pkt, list):
            for i, pkt in enumerate(send_pkt):
                if i == len(send_pkt) - 1:
                    received_set = self.packet_send_received(pkt, send_attempts, receive_attempts+50, repeat)
                else:
                    received_set = self.packet_send_received(pkt, send_attempts, send_attempts, repeat)
                if received_set:
                    received.extend(received_set)

        else:

            received = self.packet_send_received(send_pkt, send_attempts, receive_attempts, repeat)

        if received:
            for pkt in received:

                
                if True:
                    re_pkt = self.packet_construction.receive_packet_handler(pkt)
                    
                    # print(re_pkt.summary())
                    # print("----------------------------------------")
                    if re_pkt != None:
                        # print(Fore.GREEN + "RX <--- " + re_pkt.summary())
                        # print(Fore.MAGENTA + re_pkt.summary())
                        re_pkt.show2()
                        result.update(re_pkt.summary().split(" / "))
                    else:
                        # print("empty")
                        result.add("empty")
                # self.logger.debug("RX <--- " + pkt.summary())
                # pkt.show2()

                return_list = "|".join(sorted(result))
            print(Fore.GREEN + "RX <--- " + return_list)
            return return_list if return_list else constant.EMPTY
        else:
            return constant.EMPTY

    def packet_send_received(self, send_pkt: Packet, send_attempts=constant.NORMAL_SEND_ATTEMPTS,
                             receive_attempts=constant.NORMAL_RECEIVE_ATTEMPTS, repeat=None):
        pkt = None
        attempts = 0
        received_data = []
        check_data = set()
        start_time = time.time()
        self.logger.info("TX ---> " + send_pkt.summary())
        # hexdump(send_pkt)
        # send_pkt.show2()

        if hasattr(self.driver, 'is_device_connected') and not self.driver.is_device_connected():
            print(Fore.RED + "Device is not connected, attempting to reset...")
            self.driver.reset()
        print(Fore.YELLOW )
        send_pkt.show2()

        while attempts < receive_attempts:

            if attempts < send_attempts:
                try:
                    self.driver.send(send_pkt)
                except Exception as e:
                    print(Fore.RED + f"Error sending packet: {e}")
                    self.driver.reset()
                    break
            attempts = attempts + 1
            data = self.driver.raw_receive()
            if data:
                pkt = BTLE(data)
                # pkt.show2()
                if pkt is not None:
                    if pkt.haslayer('EIR Header') and pkt['EIR Header'].type in (0x29, 0x2a, 0x2b):
                        # print(Fore.MAGENTA + "RX <--- " + pkt.summary())
                        
                        if received_data == [] or (pkt["BTLE"].crc not in [p["BTLE"].crc for p in received_data]):
                            print(Fore.BLUE + "RX <--- " + pkt.summary())
                            # pkt.show2()
                            received_data.append(pkt)
                            # print(received_data)

                    elif pkt.haslayer('EIR Header') and pkt['EIR Header'].type == 0x2a:
                        # print(Fore.MAGENTA + "RX <--- " + pkt.summary())
                        pkt.show2()

        print(received_data)
        return received_data

    def packet_received_control(self, connect_receive_attempts=constant.NORMAL_RECEIVE_ATTEMPTS):
        attempts = 0
        received_data = []
        while attempts < connect_receive_attempts:
            data = self.driver.raw_receive()
            if data:
                pkt = BTLE(data)
                if pkt is not None:
                    # pkt.show2()
                    if pkt.haslayer("BTLE_ADV_NONCONN_IND"):
                        if pkt.haslayer("MeshBeacon"):
                            if pkt.haslayer("UnprovisionedDeviceBeacon") or pkt.haslayer("UnprovisionedDeviceBeaconNoURI"):
                                print(Fore.MAGENTA + "RX <--- " + pkt.summary())
                                pkt.show2()
                            else:
                                print(Fore.RED + "RX <--- " + pkt.summary())

                        # elif pkt.haslayer("NetworkPDU"):
                        #     pkt.show2()



    def pre(self):
        
        device_state = self.find_device()
        start_time = time.time()
        while device_state != "unprovisioned_device_beacon_pkt" and device_state != "secure_network_beacon_pkt" and time.time() - start_time < 100:
            print(Fore.YELLOW + "Device not in expected state, resetting device...")
            # subprocess.run(["/home/yangting/.espressif/python_env/idf5.3_py3.12_env/bin/python", "-m", "esptool", "-p", "/dev/ttyUSB0", "run"])
            # if device_state == "secure_network_beacon_pkt":
            #     print(Fore.GREEN + "Device found, already provisioned")

            sleep(2)
            device_state = self.find_device()

        if device_state == "unprovisioned_device_beacon_pkt":
            print(Fore.GREEN + "Device found, need to provision")
            

        elif device_state == "secure_network_beacon_pkt":
            self.provisioned = True
        else:
            print(Fore.RED + "Timeout: Device not found in expected state after 100 seconds")

        self.data_prepare()
        return device_state
    # response = self.presponse
    def post(self):
        print("-----------------Post Start-----------------")
        for i in range(3):
            terminate_pkt = self.get_pkt('link_close_message_pkt')
            self.packet_send_received_control(terminate_pkt)
        sleep(2)
        print("-----------------Post End-----------------")

    def step(self, input_symbol, log=False):

        if isinstance(input_symbol, list):

            received_data = []
            for input_output in input_symbol:
                if '/' in input_output:
                    send_packet = input_output.split('/')[0]
                else:
                    send_packet = input_output
                if isinstance(send_packet, Packet):
                    pkt = send_packet
                elif isinstance(send_packet, str):
                    pkt = self.get_pkt(send_packet)
                output = self.packet_send_received_control(pkt, log=True)
                # if output == constant.EMPTY:
                #     continue
                print(send_packet + "|" + output)
                received_data.append(send_packet + "|" + output)
            return received_data
            # return "|".join(str(item) for item in sorted(received_data)) if len(received_data) != 0 else None

        elif isinstance(input_symbol, str):
            # section = self.packet_construction.find_section(input_symbol)
            # pkt_dict = self.packet_process.read_config_packet(self.config_file,section)
            pkt = self.get_pkt(input_symbol)
            received_data = self.packet_send_received_control(pkt, log=True)
            return received_data
        elif isinstance(input_symbol, Packet):
            received_data = self.packet_send_received_control(input_symbol, log=True)
            return received_data
        else:
            return constant.ERROR

    def get_pkt(self, pkt_name, field_name=None, field_value=None, handle_mode=None):
        # print(f"pkt_name: {pkt_name}")
        # print(f"field_name: {field_name}")
        # print(f"field_value: {field_value}")
        return self.packet_construction.get_pkt(pkt_name, field_name, field_value, handle_mode)

    def query(self, word):

        self.performed_steps_in_query = 0
        out = constant.ERROR
        error_counter = 0
        while out == constant.ERROR and error_counter < constant.CONNECTION_ERROR_ATTEMPTS:
            self.pre()
            outputs = []
            num_steps = 0
            for letter in word:
                out = self.step(letter)
                num_steps += 1
                if out == constant.ERROR:
                    print(Fore.RED + "ERROR reported")
                    self.connection_error_counter += 1
                    self.post()
                    self.num_queries += 1
                    self.performed_steps_in_query += num_steps
                    self.num_steps += num_steps
                    break

                outputs.append(out)
            if out == constant.ERROR:
                error_counter += 1
                continue
            self.post()
            self.num_queries += 1
            self.performed_steps_in_query += len(word)
            self.num_steps += len(word)
            return outputs
        raise ConnectionError()

    def reset(self):

        pass

    def handle_sigtstp(self, signum, frame):
        print("Caught SIGTSTP (Ctrl+Z)")
        self.exit_flag = True
        print("learning exit")
        self.logger.info("learning exit")

    def find_device(self):
        start_time = time.time()
        return_type = ["unprovisioned_device_beacon_pkt", "secure_network_beacon_pkt", "mesh_private_beacon_pkt"]
        while time.time() - start_time < 100:
            data = self.driver.raw_receive()
            if data:
                pkt = BTLE(data)
                if pkt is not None:
                    # 检查是否是目标设备的广播包
                    if pkt.haslayer("BTLE_ADV_NONCONN_IND"):
                        # 检查未配网设备 Beacon
                        if pkt.haslayer("BLEMesh_Unprovisioned_Device_Beacon"):
                            beacon_layer = pkt.getlayer("BLEMesh_Unprovisioned_Device_Beacon")
                            if beacon_layer and beacon_layer.Device_UUID:
                                self.deviceuuid = beacon_layer.Device_UUID
                                print(Fore.MAGENTA + "RX <--- " + pkt.summary())
                                pkt.show()
                                return return_type[0]
                        # 检查安全网络 Beacon
                        elif pkt.haslayer("BLEMesh_Secure_Network_Beacon"):
                            print(Fore.MAGENTA + "RX <--- " + pkt.summary())
                            # pkt.show2()
                            return return_type[1]
                        
                        # 检查私有 Mesh Beacon
                        elif pkt.haslayer("BLEMesh_Mesh_Private_Beacon"):
                            print(Fore.MAGENTA + "RX <--- " + pkt.summary())
                            # pkt.show2()
                            return return_type[2]
                        
                        # 如果是目标设备的其他类型数据包，打印信息但不返回
                        else:
                            pass
                            # print(Fore.MAGENTA + "RX <--- " + pkt.summary())
                            # pkt.show2()

        return None









