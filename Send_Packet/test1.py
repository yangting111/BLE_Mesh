import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/libs/")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/libs/boofuzz/")

# from Transfer.Send_Packet.Ble_Mesh_PBADV import Ble_Mesh_PBADV
# from Transfer.Send_Packet.Ble_Mesh_Beacon import Ble_Mesh_Beacon
# from Transfer.Send_Packet.Ble_Mesh_Message import Ble_Mesh_Message
from colorama import Fore
from Transfer.Send_Packet.BluetoothMesh_SUL import BluetoothMesh_SUL
# from Transfer.Config.ST import config
from Transfer.Config.Esp32 import config
# from Transfer.Config.Zerphy import config
from Transfer.libs.driver.NRF52_dongle import NRF52Dongle
from scapy.utils import hexdump

port_name = config.device["port_name"]
logs_pcap = config.device["logs_pcap"]
pcap_filename = config.device["pcap_filename"]
key_path = config.device["key_path"]
unprovisioned_device_address = config.device["unprovisioned_device_address"]
iat = config.device["iat"]
rat = config.device["rat"]
role = config.device["role"]
rx_len = config.device["rx_len"]
tx_len = config.device["tx_len"]
logger_handle = config.device["log_path"]
algorithm = config.device["algorithm"]


#    self.pbadvpkts= ["pbadv_pkts",'link_open_message_pkt','link_ack_message_pkt','link_close_message_pkt','provisioning_invite_pkt','provisioning_capability_pkt','provisioning_start_pkt','provisioning_public_key_pkt','provisioning_confirmation_pkt','provisioning_random_pkt','provisioning_failed_pkt','transaction_acknowledgment_pkt']
#    self.beaconpkts= ["beacon_pkts",'unprovisioned_device_beacon_pkt','secure_network_beacon_pkt','mesh_private_beacon_pkt']
#    self.messagepkts= ["message_pkts",'config_composition_data_get_pkt','config_app_key_add_pkt','segment_ack_pkt']
def provision_process(blemesh_sul):
    pkt = blemesh_sul.get_pkt("link_open_message_pkt")

    receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)

    pkt = blemesh_sul.get_pkt("provisioning_invite_pkt")

    receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)

    pkt = blemesh_sul.get_pkt("transaction_acknowledgment_pkt")
    receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)

    pkt = blemesh_sul.get_pkt("provisioning_start_pkt")
    receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)

    p = blemesh_sul.get_pkt("provisioning_public_key_pkt")
    receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=p)

    pkt = blemesh_sul.get_pkt("transaction_acknowledgment_pkt")
    receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)

    pkt = blemesh_sul.get_pkt("provisioning_confirmation_pkt")
    receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)

    pkt = blemesh_sul.get_pkt("transaction_acknowledgment_pkt")
    receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)

    pkt = blemesh_sul.get_pkt("provisioning_random_pkt")
    receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)

    pkt = blemesh_sul.get_pkt("transaction_acknowledgment_pkt")
    receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)

    pkt = blemesh_sul.get_pkt("provisioning_data_pkt")
    receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)

    pkt = blemesh_sul.get_pkt("transaction_acknowledgment_pkt")
    receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)

    pkt = blemesh_sul.get_pkt("link_close_message_pkt")
    receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)

    pkt = blemesh_sul.get_pkt("config_composition_data_get_pkt")
    receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)

    pkt = blemesh_sul.get_pkt("config_node_reset_pkt")
    receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)

    # pkt = blemesh_sul.get_pkt("config_app_key_add_pkt")
    # receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)

    # subprocess.run(["/home/yangting/.espressif/python_env/idf5.3_py3.12_env/bin/python", "-m", "esptool", "-p", "/dev/ttyUSB0", "run"])

# def control_process():
#     blemesh_sul.packet_received_control()


blemesh_sul = BluetoothMesh_SUL(NRF52Dongle(port_name=port_name, logs_pcap=logs_pcap, pcap_filename=pcap_filename),
                                unprovisioned_device_address,
                                iat=iat,
                                rat=rat,
                                role=role,
                                rx_len=rx_len,
                                tx_len=tx_len,
                                logger_handle=logger_handle,
                                key_path=key_path,
                                algorithm=algorithm)

# fuzz_session = Fuzz_Session(sul=blemesh_sul, fuzz_layer=[ProvisioningPDU], logger_handle=logger_handle)

device_state = blemesh_sul.pre()


if device_state == "unprovisioned_device_beacon_pkt":
    print(Fore.GREEN + "Device found, need to provision")
    receive_pkt = ""
    while "Link_ACK_Message" not in receive_pkt:        
        pkt = blemesh_sul.get_pkt("link_open_message_pkt")
        receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)
        print(receive_pkt)
    print(Fore.GREEN + "Link_ACK_Message received")
    provision_process(blemesh_sul)
elif device_state == "secure_network_beacon_pkt":
    print(Fore.GREEN + "Device found, already in secure network")
    appkeys = blemesh_sul.packet_construction.mesh_decrypter.get_appkeys()
    devkeys = blemesh_sul.packet_construction.mesh_decrypter.get_devkeys()
    netkeys = blemesh_sul.packet_construction.mesh_decrypter.get_netkeys()
    print(f"appkeys: {appkeys[0].key.hex()}")
    print(f"devkeys: {devkeys[0].key.hex()}, address: {devkeys[0].address}")
    print(f"netkeys: {netkeys[0].key.hex()}, ivindex: {netkeys[0].iv_index}")
    # blemesh_sul.packet_construction.message_handle.seq = 900
    # pkt = blemesh_sul.get_pkt("config_node_reset_pkt")

    # receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)
else:
    pass
# blemesh_sul.post()

