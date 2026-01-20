import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/libs/")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/libs/boofuzz/")

from Transfer.Send_Packet.Ble_Mesh_PBADV import Ble_Mesh_PBADV
from Transfer.Send_Packet.Ble_Mesh_Beacon import Ble_Mesh_Beacon
from Transfer.Send_Packet.Ble_Mesh_Message import Ble_Mesh_Message
from colorama import Fore, Style, init
from Transfer.Send_Packet.BluetoothMesh_SUL import BluetoothMesh_SUL
# from Transfer.Config.Esp32 import config
from Transfer.Config.Zerphy import config
from Transfer.libs.driver.NRF52_dongle import NRF52Dongle
from Transfer.libs.scapy.compat import raw
from binascii import hexlify
from Transfer.libs.scapy.layers.bluetooth4LE import BTLE
from Transfer.libs.scapy.contrib.ble_mesh import *

from Transfer.Send_Packet.packet_factory import create_config_app_key_add, create_config_composition_data_get
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


blemesh_sul = BluetoothMesh_SUL(NRF52Dongle(port_name=port_name, logs_pcap=logs_pcap, pcap_filename=pcap_filename),
                                unprovisioned_device_address,
                                iat=iat,
                                rat=rat,
                                role=role,
                                rx_len=rx_len,
                                tx_len=tx_len,
                                logger_handle=logger_handle,
                                key_path=key_path)

# fuzz_session = Fuzz_Session(sul=blemesh_sul, fuzz_layer=[ProvisioningPDU], logger_handle=logger_handle)

# device_state = blemesh_sul.packet_received_control()
# blemesh_sul.pre()
# pkt = blemesh_sul.packet_construction.message_dict["config_composition_data_get_pkt"]
# hexdump(pkt)

# pkt.show2()
# print(pkt.summary())
# print(Fore.GREEN + "Device found, already in secure network")
blemesh_sul.provisioned = True
blemesh_sul.data_prepare()
appkeys = blemesh_sul.packet_construction.mesh_decrypter.get_appkeys()
devkeys = blemesh_sul.packet_construction.mesh_decrypter.get_devkeys()
netkeys = blemesh_sul.packet_construction.mesh_decrypter.get_netkeys()
print(f"appkeys: {appkeys[0].key.hex()}")
print(f"devkeys: {devkeys[0].key.hex()}, address: {devkeys[0].address}")
print(f"netkeys: {netkeys[0].key.hex()}, ivindex: {netkeys[0].iv_index}")

# blemesh_sul.packet_construction.message_handle.seq = 8
# pkt = blemesh_sul.get_pkt("config_node_reset_pkt")

# receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)



# blemesh_sul.packet_construction.message_handle.seq = 10

# pkt = blemesh_sul.get_pkt("config_netkey_update_pkt",field_name=["SEQ"],field_value=[48])
# receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)


# # blemesh_sul.packet_construction.mesh_decrypter.netkeys[0].netkey_set(bytes.fromhex("9ae0b2f02b2e7c555ae169a45bdc1da3"))
# # pkt = blemesh_sul.get_pkt("config_key_refresh_phase_get_pkt",field_name=["SEQ"],field_value=[308])
# # receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)


# pkt = blemesh_sul.get_pkt("config_key_refresh_phase_set_pkt",field_name=["SEQ","transition"],field_value=[56,3])
# receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)

# pkt = blemesh_sul.get_pkt("config_app_key_add_pkt",field_name=["SEQ"],field_value=[410],handle_mode="remove")
# receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)
# pkt = blemesh_sul.get_pkt("config_app_key_add_pkt",field_name=["SEQ","net_key_index","app_key_index","app_key"],field_value=[430,0,0,bytes.fromhex("12"*16)])
# receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)




# pkt = blemesh_sul.get_pkt("config_app_key_delete_pkt",field_name=["SEQ","net_key_index","app_key_index"],field_value=[418,0,0])
# receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)

pkt = blemesh_sul.get_pkt("config_app_key_get_pkt",field_name=["SEQ","net_key_index"],field_value=[432,0])
receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)

# blemesh_sul.packet_construction.mesh_decrypter.netkeys[0].netkey_set(bytes.fromhex("4429a62c631a42ed4af1d0ac5973c8c7"))
# pkt = blemesh_sul.get_pkt("config_key_refresh_phase_get_pkt",field_name=["SEQ"],field_value=[52])

# receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)
# # pkt = blemesh_sul.get_pkt("config_key_refresh_phase_get_pkt",field_name=["SEQ"],field_value=[26])
# # pkt = blemesh_sul.get_pkt("config_key_refresh_phase_set_pkt",field_name=["SEQ","transition"],field_value=[38,3])
# # receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)

# pkt = blemesh_sul.get_pkt("config_netkey_delete_pkt",field_name=["SEQ"],field_value=[54])
# # pkt = blemesh_sul.get_pkt("config_netkey_get_pkt")
# # for p in pkt:
# #     hexdump(p)
# receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)



# pkt = blemesh_sul.get_pkt("config_key_refresh_phase_get_pkt",field_name=["SEQ"],field_value=[40])
# receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)


# pkt = blemesh_sul.get_pkt("config_node_reset_pkt",field_name=["SEQ"],field_value=[304])
# receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)

# pkt = blemesh_sul.get_pkt("config_netkey_update_pkt",field_name=["SEQ"],field_value=[34])
# # pkt = blemesh_sul.get_pkt("config_netkey_get_pkt")
# # for p in pkt:
# #     hexdump(p)
# receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)



# blemesh_sul.pre()
# pkt2 = blemesh_sul.get_pkt("segment_ack_pkt")
# pkt2.show2()
# print(pkt2.summary())

# for pkt in pkt_list:
#     pkt.show2()
#     print(pkt.summary())
#     raw_pkt = raw(pkt)
#     pkt1 = BTLE(raw_pkt)
#     pkt1.show2()
#     print(pkt1.summary())






# for i in pkt:
#     print(i.summary())
#     raw_pkt = raw(i)
#     print(hexlify(raw_pkt).upper())

#     re_pkt = BTLE(raw_pkt)
#     re_pkt.show2()
#     print(re_pkt.summary())
    # i.show()
    # i.show2()



