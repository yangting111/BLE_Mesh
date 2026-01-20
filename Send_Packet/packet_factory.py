"""
数据包创建工厂函数
用于创建各种 BLE Mesh 数据包
"""
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/../../")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/../libs/")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/../libs/boofuzz/")

from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from scapy.packet import Packet, raw, Raw
from scapy.contrib.ble_mesh import *


# ==================== PB-ADV 相关函数 ====================

def create_link_open():
    """创建 Link Open 消息"""
    pkt = BTLE() / BTLE_ADV() / BTLE_ADV_NONCONN_IND() / EIR_Hdr(type=0x29) / BLEMesh_PBADV() / BLEMesh_Provisioning_Bearer_Control(
        BearerOpcode=0, GPCF=3) / Link_Open_Message()
    return pkt


def create_link_ack():
    """创建 Link ACK 消息"""
    pkt = BTLE() / BTLE_ADV() / BTLE_ADV_NONCONN_IND() / EIR_Hdr(type=0x29) / BLEMesh_PBADV() / BLEMesh_Provisioning_Bearer_Control(
        BearerOpcode=1, GPCF=3) / Link_ACK_Message()
    return pkt


def create_link_close():
    """创建 Link Close 消息"""
    pkt = BTLE() / BTLE_ADV() / BTLE_ADV_NONCONN_IND() / EIR_Hdr(type=0x29) / BLEMesh_PBADV() / BLEMesh_Provisioning_Bearer_Control(
        BearerOpcode=2, GPCF=3) / Link_Close_Message()
    return pkt


def create_transaction_acknowledgment():
    """创建 Transaction Acknowledgment"""
    pkt = BTLE() / BTLE_ADV() / BTLE_ADV_NONCONN_IND() / EIR_Hdr(type=0x29) / BLEMesh_PBADV() / Transaction_Acknowledgment_PDU()
    return pkt


def create_provisioning_invite():
    """创建 Provisioning Invite"""
    pkt = BLEMesh_Provisioning_PDU(PDU_Type=0) / Provisioning_Invite()
    return pkt


def create_provisioning_capabilities():
    """创建 Provisioning Capabilities"""
    pkt = BLEMesh_Provisioning_PDU(PDU_Type=1) / Provisioning_Capabilities()
    return pkt


def create_provisioning_start():
    """创建 Provisioning Start"""
    pkt = BLEMesh_Provisioning_PDU(PDU_Type=2) / Provisioning_Start()
    return pkt


def create_provisioning_public_key():
    """创建 Provisioning Public Key"""
    pkt = BLEMesh_Provisioning_PDU(PDU_Type=3) / Provisioning_Public_Key()
    return pkt


def create_provisioning_confirmation():
    """创建 Provisioning Confirmation"""
    pkt = BLEMesh_Provisioning_PDU(PDU_Type=5) / Provisioning_Confirmation()
    return pkt


def create_provisioning_random():
    """创建 Provisioning Random"""
    pkt = BLEMesh_Provisioning_PDU(PDU_Type=6) / Provisioning_Random()
    return pkt


def create_provisioning_data():
    """创建 Provisioning Data"""
    pkt = BLEMesh_Provisioning_PDU(PDU_Type=7) / Provisioning_Data()
    return pkt


def create_provisioning_complete():
    """创建 Provisioning Complete"""
    pkt = BLEMesh_Provisioning_PDU(PDU_Type=8) / Provisioning_Complete()
    return pkt


def create_provisioning_failed():
    """创建 Provisioning Failed"""
    pkt = BLEMesh_Provisioning_PDU(PDU_Type=9) / Provisioning_Failed()
    return pkt



# ==================== Config Message 相关函数 ====================
"""
Config Message 特点:
1. 使用 DevKey 加密 (AKF=0, AID=0)
2. 大部分消息较小 (≤11字节)，使用 Unsegmented Access Message
3. 少数消息较大 (≥12字节)，使用 Segmented Access Message

需要分段的 Config Message (≥12字节):
- Config App Key Add (19字节)
- Config App Key Update (19字节)  
- Config Model Publication Set (13-15字节)
- Config App Key List (可变长度)
- Config Composition Data Status (可变长度，通常较大)

自动分段判断规则:
- 明文长度 ≤ 11 字节: Unseg_Access_Message (SEG=0)
- 明文长度 ≥ 12 字节: Seg_Access_Message (SEG=1, SZMIC=0)
"""

def create_config_beacon_get():
    """
    创建 Config Beacon Get
    Opcode: 0x8009 (1字节) - 不分段
    """
    payload = ConfigBeaconGet()
    # Config Beacon Get 只有 opcode，≤11字节，不分段
    pkt = Message_Decode(CTL=0) / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / payload
    return pkt


def create_config_beacon_set(beacon=1):
    """
    创建 Config Beacon Set
    Opcode: 0x800A (1字节) + Beacon(1字节) = 2字节 - 不分段
    """
    payload = ConfigBeaconSet(beacon=beacon)
    # ≤11字节，不分段
    pkt = Message_Decode(CTL=0) / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / payload
    return pkt


def create_config_beacon_status(beacon=1):
    """
    创建 Config Beacon Status
    Opcode: 0x800B (1字节) + Beacon(1字节) = 2字节 - 不分段
    """
    payload = ConfigBeaconStatus(beacon=beacon)
    # ≤11字节，不分段
    pkt = Message_Decode(CTL=0) / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / payload
    return pkt


def create_config_composition_data_get(page=0):
    """
    创建 Config Composition Data Get
    Opcode: 0x8008 (1字节) + Page(1字节) = 2字节 - 不分段
    """
    payload = ConfigCompositionDataGet()
    # ≤11字节，不分段
    pkt = Message_Decode(CTL=0) / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / payload
    return pkt


def create_config_default_ttl_get():
    """
    创建 Config Default TTL Get
    Opcode: 0x800C (1字节) - 不分段
    """
    payload = ConfigDefaultTTLGet()
    # ≤11字节，不分段
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / payload
    return pkt


def create_config_default_ttl_set(ttl=5):
    """
    创建 Config Default TTL Set
    Opcode: 0x800D (1字节) + TTL(1字节) = 2字节 - 不分段
    """
    payload = ConfigDefaultTTLSet()
    # ≤11字节，不分段
    pkt = Message_Decode(CTL=0) / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / payload
    return pkt


def create_config_default_ttl_status(ttl=5):
    """
    创建 Config Default TTL Status
    Opcode: 0x800E (1字节) + TTL(1字节) = 2字节 - 不分段
    """
    payload = ConfigDefaultTTLStatus()
    # ≤11字节，不分段
    pkt = Message_Decode(CTL=0) / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / payload
    return pkt


def create_config_gatt_proxy_get():
    """
    创建 Config GATT Proxy Get
    Opcode: 0x8012 (1字节) - 不分段
    """
    payload = ConfigGATTProxyGet()
    # ≤11字节，不分段
    pkt = Message_Decode(CTL=0) / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / payload
    return pkt


def create_config_gatt_proxy_set(gatt_proxy=1):
    """
    创建 Config GATT Proxy Set
    Opcode: 0x8013 (1字节) + GATT_Proxy(1字节) = 2字节 - 不分段
    """
    payload = ConfigGATTProxySet()
    # ≤11字节，不分段
    pkt = Message_Decode(CTL=0) / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / payload
    return pkt


def create_config_gatt_proxy_status(gatt_proxy=1):
    """
    创建 Config GATT Proxy Status
    Opcode: 0x8014 (1字节) + GATT_Proxy(1字节) = 2字节 - 不分段
    """
    payload = ConfigGATTProxyStatus()
    # ≤11字节，不分段
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / payload
    return pkt


def create_config_relay_get():
    """创建 Config Relay Get"""
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / Raw(b"\x80\x26")  # Opcode 0x8026
    return pkt


def create_config_relay_set():
    """创建 Config Relay Set"""
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / Raw(b"\x80\x27\x01\x00")  # Opcode 0x8027, relay=1, retransmit_count=0
    return pkt


def create_config_relay_status():
    """创建 Config Relay Status"""
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / Raw(b"\x80\x28\x01\x00")  # Opcode 0x8028, relay=1, retransmit_count=0
    return pkt


def create_config_model_publication_get():
    """创建 Config Model Publication Get"""
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / Raw(b"\x80\x18\x00\x00\x00\x00")  # Opcode 0x8018, element_address, model_id
    return pkt


def create_config_model_publication_set():
    """
    创建 Config Model Publication Set
    Opcode: 0x03 (1字节) + ElementAddress(2字节) + PublishAddress(2字节) + 
            AppKeyIndex(2字节) + CredentialFlag(1bit) + RFU(7bits) + 
            PublishTTL(1字节) + PublishPeriod(1字节) + PublishRetransmit(1字节) + ModelID(2/4字节)
    总计: 约 13-15 字节，需要分段
    """
    payload = Raw(b"\x80\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")  # Opcode 0x03
    payload_len = len(raw(payload))
    
    # 16字节 ≥ 12，需要分段
    if payload_len >= 12:
        pkt = Message_Decode() / Seg_Access_Message(SEG=1, AKF=0, AID=0, SZMIC=0) / payload
    else:
        pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / payload
    return pkt


def create_config_model_publication_virtual_address_set():
    """创建 Config Model Publication Virtual Address Set"""
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / Raw(b"\x80\x04")  # Opcode 0x8004
    return pkt


def create_config_model_publication_status():
    """创建 Config Model Publication Status"""
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / Raw(b"\x80\x19")  # Opcode 0x8019
    return pkt


def create_config_model_subscription_add():
    """创建 Config Model Subscription Add"""
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / Raw(b"\x80\x1B")  # Opcode 0x801B
    return pkt


def create_config_model_subscription_virtual_address_add():
    """创建 Config Model Subscription Virtual Address Add"""
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / Raw(b"\x80\x20")  # Opcode 0x8020
    return pkt


def create_config_model_subscription_delete():
    """创建 Config Model Subscription Delete"""
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / Raw(b"\x80\x1C")  # Opcode 0x801C
    return pkt


def create_config_model_subscription_virtual_address_delete():
    """创建 Config Model Subscription Virtual Address Delete"""
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / Raw(b"\x80\x21")  # Opcode 0x8021
    return pkt


def create_config_model_subscription_overwrite():
    """创建 Config Model Subscription Overwrite"""
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / Raw(b"\x80\x1D")  # Opcode 0x801D
    return pkt


def create_config_model_subscription_virtual_address_overwrite():
    """创建 Config Model Subscription Virtual Address Overwrite"""
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / Raw(b"\x80\x22")  # Opcode 0x8022
    return pkt


def create_config_model_subscription_status():
    """创建 Config Model Subscription Status"""
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / Raw(b"\x80\x1F")  # Opcode 0x801F
    return pkt


def create_config_sig_model_subscription_get():
    """创建 Config Sig Model Subscription Get"""
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / Raw(b"\x80\x29")  # Opcode 0x8029
    return pkt


def create_config_sig_model_subscription_list():
    """创建 Config Sig Model Subscription List"""
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / Raw(b"\x80\x2A")  # Opcode 0x802A
    return pkt


def create_config_vendor_model_subscription_get():
    """创建 Config Vendor Model Subscription Get"""
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / Raw(b"\x80\x2B")  # Opcode 0x802B
    return pkt


def create_config_vendor_model_subscription_list():
    """创建 Config Vendor Model Subscription List"""
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / Raw(b"\x80\x2C")  # Opcode 0x802C
    return pkt


def create_config_netkey_add():
    """创建 Config NetKey Add"""
    netkey_add = ConfigNetworkKeyAdd()
    pkt = Message_Decode() /Seg_Access_Message(SEG=1, AKF=0, AID=0, SZMIC=1) / netkey_add # Opcode 0x8040
    return pkt


def create_config_netkey_update():
    """创建 Config NetKey Update"""
    netkey_update = ConfigNetworkKeyUpdate()
    pkt = Message_Decode() / Seg_Access_Message(SEG=1, AKF=0, AID=0) / netkey_update # Opcode 0x8045
    return pkt


def create_config_netkey_delete():
    """创建 Config NetKey Delete"""
    netkey_delete = ConfigNetworkKeyDelete()
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / netkey_delete # Opcode 0x8041
    return pkt


def create_config_netkey_status():
    """创建 Config NetKey Status"""
    netkey_status = ConfigNetworkKeyStatus()
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / netkey_status # Opcode 0x8044
    return pkt


def create_config_netkey_get():
    """创建 Config NetKey Get"""
    netkey_get = ConfigNetworkKeyGet()
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / netkey_get # Opcode 0x8024
    return pkt


def create_config_netkey_list():
    """创建 Config NetKey List"""
    netkey_list = ConfigNetworkKeyList()
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / netkey_list # Opcode 0x8043
    return pkt


def create_config_app_key_add(net_key_index=0, app_key_index=0, app_key=b''):
    """
    创建 Config App Key Add
    Opcode: 0x00 (1字节) + NetKeyIndex(1.5字节) + AppKeyIndex(0.5字节) + AppKey(16字节) = 19字节
    注意：19字节 ≥ 12，需要分段
    """
    payload = ConfigAppKeyAdd()
    # payload_len = len(raw(payload))
    
    # 判断是否需要分段（≥12字节需要分段）

        # 需要分段，使用 Seg_Access_Message
    pkt = Message_Decode() / Seg_Access_Message(SEG=1, AKF=0, AID=0, SZMIC=0) / payload
    return pkt


def create_config_app_key_update(net_key_index=0, app_key_index=0, app_key=b''):
    """
    创建 Config App Key Update
    Opcode: 0x01 (1字节) + NetKeyIndex(1.5字节) + AppKeyIndex(0.5字节) + AppKey(16字节) = 19字节
    注意：19字节 ≥ 12，需要分段
    """
    payload = ConfigAppKeyUpdate()
    pkt = Message_Decode() / Seg_Access_Message(SEG=1, AKF=0, AID=0, SZMIC=0) / payload
    return pkt


def create_config_app_key_delete(net_key_index=0, app_key_index=0):
    """
    创建 Config App Key Delete
    Opcode: 0x8000 (2字节) + NetKeyIndex(1.5字节) + AppKeyIndex(0.5字节) = 4字节 - 不分段
    """
    payload = ConfigAppKeyDelete()
    # ≤11字节，不分段
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / payload
    return pkt


def create_config_app_key_status(status=0, net_key_index=0, app_key_index=0):
    """
    创建 Config App Key Status
    Opcode: 0x8003 (2字节) + Status(1字节) + NetKeyIndex(1.5字节) + AppKeyIndex(0.5字节) = 5字节 - 不分段
    """
    payload = ConfigAppKeyStatus()
    # ≤11字节，不分段
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / payload
    return pkt


def create_config_app_key_get(net_key_index=0):
    """
    创建 Config App Key Get
    Opcode: 0x8001 (2字节) + NetKeyIndex(2字节) = 4字节 - 不分段
    """
    payload = ConfigAppKeyGet()
    # ≤11字节，不分段
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / payload
    return pkt


def create_config_app_key_list(status=0, net_key_index=0, app_key_indexes=None):
    """
    创建 Config App Key List
    Opcode: 0x8002 (2字节) + Status(1字节) + NetKeyIndex(2字节) + AppKeyIndexes(可变长度)
    注意：长度可变，可能需要分段
    """
    payload = ConfigAppKeyList()
    payload_len = len(raw(payload))
    
    if payload_len >= 12:
        pkt = Message_Decode() / Seg_Access_Message(SEG=1, AKF=0, AID=0, SZMIC=0) / payload
    else:
        pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / payload
    return pkt


def create_config_node_identity_get():
    """创建 Config Node Identity Get"""
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / Raw(b"\x80\x46")  # Opcode 0x8046
    return pkt


def create_config_node_identity_set():
    """创建 Config Node Identity Set"""
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / Raw(b"\x80\x47")  # Opcode 0x8047
    return pkt


def create_config_node_identity_status():
    """创建 Config Node Identity Status"""
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / Raw(b"\x80\x48")  # Opcode 0x8048
    return pkt


def create_config_model_app_bind(element_address=0x0500, app_key_index=0x0000, model_id=0x0010):
    """创建 Config Model App Bind
    
    Args:
        element_address: 元素地址 (2 bytes)
        app_key_index: AppKey 索引 (2 bytes)
        model_id: SIG Model ID (2 bytes) 或 Vendor Model ID (4 bytes)
    """

    payload = ConfigModelAppBind()
    # payload.show2()
    payload.element_address = element_address
    payload.app_key_index = app_key_index
    payload.model_identifier = model_id
    
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / payload
    return pkt


def create_config_model_app_status(status=0, element_address=0x0001, app_key_index=0x0000, model_id=0x1000):
    """创建 Config Model App Status
    
    Args:
        status: 状态码 (1 byte)
        element_address: 元素地址 (2 bytes)
        app_key_index: AppKey 索引 (2 bytes)
        model_id: SIG Model ID (2 bytes) 或 Vendor Model ID (4 bytes)
    """
    # Opcode 0x803E + Status + ElementAddress + AppKeyIndex + ModelIdentifier
    payload = b"\x80\x3E"  # Opcode
    payload += status.to_bytes(1, 'little')           # Status
    payload += element_address.to_bytes(2, 'little')  # ElementAddress
    payload += app_key_index.to_bytes(2, 'little')    # AppKeyIndex
    # ModelIdentifier: 2 bytes for SIG, 4 bytes for Vendor
    if model_id <= 0xFFFF:
        payload += model_id.to_bytes(2, 'little')  # SIG Model ID
    else:
        payload += model_id.to_bytes(4, 'little')  # Vendor Model ID
    
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / Raw(payload)
    return pkt


def create_config_model_app_unbind(element_address=0x0500, app_key_index=0x0000, model_id=0x0010):
    """创建 Config Model App Unbind
    
    Args:
        element_address: 元素地址 (2 bytes)
        app_key_index: AppKey 索引 (2 bytes)
        model_id: SIG Model ID (2 bytes) 或 Vendor Model ID (4 bytes)
    """
    payload = ConfigModelAppUnbind()
    payload.element_address = element_address
    payload.app_key_index = app_key_index
    payload.model_identifier = model_id
    
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / payload
    return pkt


def create_config_sig_model_app_get():
    """创建 Config Sig Model App Get"""
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / Raw(b"\x80\x40")  # Opcode 0x8040
    return pkt


def create_config_sig_model_app_list():
    """创建 Config Sig Model App List"""
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / Raw(b"\x80\x41")  # Opcode 0x8041
    return pkt


def create_config_vendor_model_app_get():
    """创建 Config Vendor Model App Get"""
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / Raw(b"\x80\x42")  # Opcode 0x8042
    return pkt


def create_config_vendor_model_app_list():
    """创建 Config Vendor Model App List"""
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / Raw(b"\x80\x43")  # Opcode 0x8043
    return pkt


def create_config_node_reset():
    """创建 Config Node Reset"""
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / Raw(b"\x80\x49")  # Opcode 0x8049
    return pkt


def create_config_node_reset_status():
    """创建 Config Node Reset Status"""
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / Raw(b"\x80\x4A")  # Opcode 0x804A
    return pkt


def create_config_friend_get():
    """创建 Config Friend Get"""
    payload = ConfigFriendGet()
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / payload # Opcode 0x802D
    return pkt


def create_config_friend_set(friend=1):
    """创建 Config Friend Set"""
    payload = ConfigFriendSet()
    payload.friend = friend
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / payload # Opcode 0x802E
    return pkt


def create_config_friend_status(friend=1):
    """创建 Config Friend Status"""
    payload = ConfigFriendStatus()
    payload.friend = friend
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / payload # Opcode 0x802F
    return pkt


def create_config_key_refresh_phase_get():
    """创建 Config Key Refresh Phase Get"""
    pdu = ConfigKeyRefreshPhaseGet()
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / pdu  # Opcode 0x8044
    return pkt


def create_config_key_refresh_phase_set():
    """创建 Config Key Refresh Phase Set"""
    pdu = ConfigKeyRefreshPhaseSet()
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / pdu  # Opcode 0x8045
    return pkt


def create_config_key_refresh_phase_status():
    """创建 Config Key Refresh Phase Status"""
    pdu = ConfigKeyRefreshPhaseStatus()
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / pdu  # Opcode 0x8010
    return pkt


def create_config_heartbeat_publication_get():
    """创建 Config Heartbeat Publication Get"""
    pdu = ConfigHeartbeatPublicationGet()
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / pdu  # Opcode 0x8038
    return pkt


def create_config_heartbeat_publication_set():
    """创建 Config Heartbeat Publication Set"""
    pdu = ConfigHeartbeatPublicationSet()
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / pdu  # Opcode 0x8039
    return pkt


def create_config_heartbeat_publication_status():
    """创建 Config Heartbeat Publication Status"""
    pdu = ConfigHeartbeatPublicationStatus()
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / pdu  # Opcode 0x8006
    return pkt


def create_config_heartbeat_subscription_get():
    """创建 Config Heartbeat Subscription Get"""
    pdu = ConfigHeartbeatSubscriptionGet()
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / pdu  # Opcode 0x803A
    return pkt


def create_config_heartbeat_subscription_set():
    """创建 Config Heartbeat Subscription Set"""
    pdu = ConfigHeartbeatSubscriptionSet()
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / pdu  # Opcode 0x803B
    return pkt


def create_config_heartbeat_subscription_status():
    """创建 Config Heartbeat Subscription Status"""
    pdu = ConfigHeartbeatSubscriptionStatus()
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / pdu  # Opcode 0x803C
    return pkt


def create_config_low_power_node_poll_timeout_get():
    """创建 Config Low Power Node Poll Timeout Get"""
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / Raw(b"\x80\x2D")  # Opcode 0x802D
    return pkt


def create_config_low_power_node_poll_timeout_status():
    """创建 Config Low Power Node Poll Timeout Status"""
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / Raw(b"\x80\x2E")  # Opcode 0x802E
    return pkt


def create_config_network_transmit_get():
    """创建 Config Network Transmit Get"""
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / Raw(b"\x80\x23")  # Opcode 0x8023
    return pkt


def create_config_network_transmit_set():
    """创建 Config Network Transmit Set"""
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / Raw(b"\x80\x24")  # Opcode 0x8024
    return pkt


def create_config_network_transmit_status():
    """创建 Config Network Transmit Status"""
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=0, AID=0) / Raw(b"\x80\x25")  # Opcode 0x8025
    return pkt


# ==================== Lower Transport Control Messages ====================

def create_segment_ack(obo=0, seq_zero=0, block_ack=0x00000003, 
                       ivi=0, nid=0x59, ttl=7, seq=1, src=1, dst=5):
    """创建 Segment ACK (Lower Transport Control Message)
    
    Args:
        obo: On Behalf Of flag - 0表示由接收消息的节点直接响应
        seq_zero: SeqZero value (13位) - 被确认消息的SeqZero
        block_ack: BlockAck bitmap (32位) - 指示哪些段已接收
        ivi: IV Index最低位 (1位)
        nid: Network ID (7位)
        ttl: Time To Live
        seq: Sequence Number (24位)
        src: Source Address
        dst: Destination Address
    
    Returns:
        Scapy packet: 完整的Segment ACK数据包
    
    Example:
        根据Wireshark抓包示例:
        NID: 89 (0x59), CTL: 1, TTL: 7
        SEQ: 1, SRC: 1, DST: 5
        TransportPDU: 00000000000003
        Lower Transport: SEG=0, Opcode=0, OBO=0, SeqZero=0, BlockAck=3
    """
    # 构建 Segment ACK payload
    payload = SegmentAckPayload(
        OBO=obo,          # 1位: 是否代表其他节点响应
        SeqZero=seq_zero, # 13位: 被确认的消息的SeqZero
        BlockAck=block_ack # 32位: 块确认位图
    )
    
    # 构建完整的数据包
    # Message_Decode: 网络层头部
    # Control_Message: 下传输层控制消息头部 (SEG=0表示未分段, Opcode=0表示Segment ACK)
    pkt = Message_Decode(
        IVI=ivi,
        NID=nid,
        CTL=1,        # Control Message
        TTL=ttl,
        SEQ=seq,
        SRC=src,
        DST=dst
    ) / Control_Message(
        SEG=0,        # 未分段的控制消息
        Opcode=0x00   # Segment Acknowledgment
    ) / payload
    
    return pkt


# ==================== Upper Transport Control Messages ====================

def create_heartbeat():
    """创建 Heartbeat (Upper Transport Control Message)"""
    # Heartbeat: Opcode 0x0A
    pkt = Message_Decode(CTL=1) / Control_Message(SEG=0, Opcode=0x0A) / Heartbeat()
    return pkt


def create_friend_poll():
    """创建 Friend Poll (Upper Transport Control Message)"""
    # Friend Poll: Opcode 0x01
    pkt = Message_Decode(CTL=1) / Control_Message(SEG=0, Opcode=0x01) / Friend_Poll()
    return pkt


def create_friend_update():
    """创建 Friend Update (Upper Transport Control Message)"""
    # Friend Update: Opcode 0x02
    pkt = Message_Decode(CTL=1) / Control_Message(SEG=0, Opcode=0x02) / Friend_Update()
    return pkt


def create_friend_request():
    """创建 Friend Request (Upper Transport Control Message)"""
    # Friend Request: Opcode 0x03
    pkt = Message_Decode(CTL=1) / Control_Message(SEG=0, Opcode=0x03) / Friend_Request()
    return pkt


def create_friend_offer():
    """创建 Friend Offer (Upper Transport Control Message)"""
    # Friend Offer: Opcode 0x04
    pkt = Message_Decode(CTL=1) / Control_Message(SEG=0, Opcode=0x04) / Friend_Offer()
    return pkt


def create_friend_clear():
    """创建 Friend Clear (Upper Transport Control Message)"""
    # Friend Clear: Opcode 0x05
    pkt = Message_Decode(CTL=1) / Control_Message(SEG=0, Opcode=0x05) / Friend_Clear()
    return pkt


def create_friend_clear_confirm():
    """创建 Friend Clear Confirm (Upper Transport Control Message)"""
    # Friend Clear Confirm: Opcode 0x06
    pkt = Message_Decode(CTL=1) / Control_Message(SEG=0, Opcode=0x06) / Friend_Clear_Confirm()
    return pkt


def create_friend_subscription_list_add():
    """创建 Friend Subscription List Add (Upper Transport Control Message)"""
    # Friend Subscription List Add: Opcode 0x07
    pkt = Message_Decode(CTL=1) / Control_Message(SEG=0, Opcode=0x07) / Friend_Subscription_List_Add()
    return pkt


def create_friend_subscription_list_remove():
    """创建 Friend Subscription List Remove (Upper Transport Control Message)"""
    # Friend Subscription List Remove: Opcode 0x08
    pkt = Message_Decode(CTL=1) / Control_Message(SEG=0, Opcode=0x08) / Friend_Subscription_List_Remove()
    return pkt


def create_friend_subscription_list_confirm():
    """创建 Friend Subscription List Confirm (Upper Transport Control Message)"""
    # Friend Subscription List Confirm: Opcode 0x09
    pkt = Message_Decode(CTL=1) / Control_Message(SEG=0, Opcode=0x09) / Friend_Subscription_List_Confirm()
    return pkt

def create_generic_onoff_get():
    """创建 Generic OnOff Get"""
    payload = GenericOnOffGet()
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=1, AID=0) / payload
    return pkt


def create_config_model_subscription_add(element_address=0x0001, address=0xC000, model_identifier=0x1000):
    """创建 Config Model Subscription Add
    
    Args:
        element_address: 元素地址 (2 bytes)
        address: 要添加到订阅列表的组地址 (2 bytes)
        model_identifier: SIG Model ID (2 bytes) 或 Vendor Model ID (4 bytes)
    """
    payload = ConfigModelSubscriptionAdd()
    payload.element_address = element_address
    payload.address = address
    payload.model_identifier = model_identifier
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=1, AID=0) / payload
    return pkt

def create_config_model_subscription_delete(element_address=0x0001, address=0xC000, model_identifier=0x1000):
    """创建 Config Model Subscription Delete
    
    Args:
        element_address: 元素地址 (2 bytes)
        address: 要删除的组地址 (2 bytes)
        model_identifier: SIG Model ID (2 bytes) 或 Vendor Model ID (4 bytes)
    """
    payload = ConfigModelSubscriptionDelete()
    payload.element_address = element_address
    payload.address = address
    payload.model_identifier = model_identifier
    pkt = Message_Decode() / Unseg_Access_Message(SEG=0, AKF=1, AID=0) / payload
    return pkt