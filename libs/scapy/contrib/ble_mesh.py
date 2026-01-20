# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) 2016 Anmol Sarma <me@anmolsarma.in>

# scapy.contrib.description = Constrained Application Protocol (CoAP)
# scapy.contrib.status = loads

"""

"""

# from scapy.layers.bluetooth4LE import *
# from scapy.layers.bluetooth import *
from scapy.utils import *
from scapy.packet import Packet, bind_layers, Raw, NoPayload
from scapy.error import warning
from scapy.compat import raw
from typing import Any, List
from scapy.utils import issubtype
from scapy.fields import (
    XIntField,
    BitEnumField,
    BitField,
    ByteEnumField,
    ByteField,
    IntField,
    ShortField,
    StrFixedLenField,
    StrField,
    StrLenField,
    UUIDField,
    LongField,
    ThreeBytesField,
    ConditionalField,
    LEIntField,
    LEShortField,
    X3BytesField,
)
from ble_mesh_decrypter import *



##################################
#   BLEMesh_Provisioning_Proxy   #
##################################

class BLEMesh_Provisioning_Proxy(Packet):
    name = "BLEMesh_Provisioning_Proxy"
    fields_desc = [
        BitEnumField("SAR", 0, 2, {0: "complete message", 1: "first segment", 2: "continuation", 3: "last segment"}),
        BitEnumField("Proxy_Type", 0, 6,
                     {0: "Network PDU", 1: "Mesh Beacon", 2: "Proxy Configuration", 3: "Mesh Provisioning PDU"}),
    ]


##########################
#   BLEMesh_Data_Proxy   #
##########################

class BLEMesh_Data_Proxy(Packet):
    name = "BLEMesh_Data_Proxy"
    fields_desc = [
        BitEnumField("SAR", 0, 2, {0: "complete message", 1: "first segment", 2: "continuation", 3: "last segment"}),
        BitEnumField("Proxy_Type", 0, 6,
                     {0: "Network PDU", 1: "Mesh Beacon", 2: "Proxy Configuration", 3: "Mesh Provisioning PDU"}),
    ]


#####################
#   BLEMesh_Adv     #
#####################

class Transaction_Start_PDU(Packet):
    name = "Transaction_Start_PDU"
    fields_desc = [
        BitField("SegN", 0, 6),
        BitField("GPCF", 0, 2),
        ShortField("len", 0),
        ByteField("FCS", None)
    ]
    
    def guess_payload_class(self, payload):
        if not payload:
            return Raw
        # Transaction_Start_PDU 之后应该是 BLEMesh_Provisioning_PDU
        return BLEMesh_Provisioning_PDU


class Transaction_Acknowledgment_PDU(Packet):
    name = "Transaction_Acknowledgment_PDU"
    fields_desc = [
        BitField("Padding", 0, 6),
        BitField("GPCF", 1, 2),  # GPCF=1 表示 Transaction Acknowledgment
    ]


class Transaction_Continuation_PDU(Packet):
    name = "Transaction_Continuation_PDU"
    fields_desc = [
        BitField("SegmentIndex", 0, 6),
        BitField("GPCF", 2, 2),  # GPCF=2 表示 Transaction Continuation
    ]
    
    def guess_payload_class(self, payload):
        # Transaction_Continuation_PDU 之后是 Provisioning PDU 的分片数据
        # 保持为 Raw，因为这是分片的中间部分
        return Raw


class BLEMesh_PBADV(Packet):
    name = "BLEMesh_PBADV"
    # LinkId distincts two device
    # TransNum disticts two fragment packet
    fields_desc = [XIntField("LinkId", 0x01),
                   ByteField("TransNum", 0),
                   ]

    def guess_payload_class(self, payload):
        if not payload:
            return Raw
        first_byte = payload[0] if isinstance(payload[0], int) else ord(payload[0])
        gpcf = first_byte & 0x03
        if gpcf == 0:
            return Transaction_Start_PDU
        elif gpcf == 1:
            return Transaction_Acknowledgment_PDU
        elif gpcf == 2:
            return Transaction_Continuation_PDU
        elif gpcf == 3:
            return BLEMesh_Provisioning_Bearer_Control
        return Raw

    def fragment(self, pkt, fragsize=24):
        """Fragment a big PB-ADV datagram"""
        p = pkt
        lst = []
        if not p.haslayer('BLEMesh_Provisioning_PDU'):
            return p
        total_len = len(raw(p.getlayer('BLEMesh_Provisioning_PDU')))
        nb = total_len // 24 + 1
        for i in range(nb):
            if i == 0:
                f = BLEMesh_PBADV(LinkId=p.LinkId, TransNum=p.TransNum) / Transaction_Start_PDU(Seg_num=nb,
                                                                                                len=total_len, FCS=crc8(
                        raw(p.getlayer(BLEMesh_Provisioning_PDU)))) / raw(p.getlayer('BLEMesh_Provisioning_PDU'))[0:20]
            elif i == nb - 1:
                f = BLEMesh_PBADV(LinkId=p.LinkId, TransNum=p.TransNum) / Transaction_Continuation_PDU(Seg_num=i) / raw(
                    p.getlayer(BLEMesh_Provisioning_PDU))[20 + (i - 1) * (fragsize - 1):]
            else:
                f = BLEMesh_PBADV(LinkId=p.LinkId, TransNum=p.TransNum) / Transaction_Continuation_PDU(Seg_num=i) / raw(
                    p.getlayer(BLEMesh_Provisioning_PDU))[20 + (i - 1) * (fragsize - 1):i * (fragsize - 1) + 20]
            lst.append(f)
        return lst


#########################
#  BLEMesh_Provisioning #
#########################

class BLEMesh_Provisioning_Bearer_Control(Packet):
    name = "BLEMesh_Provisioning_Bearer_Control"
    fields_desc = [
        BitField("BearerOpcode", 0, 6),
        BitField("GPCF", 3, 2),
    ]

    def guess_payload_class(self, payload):
        if not payload:
            cls = self._get_opcode_cls()
            return cls if cls else Raw
        first_byte = payload[0] if isinstance(payload[0], int) else ord(payload[0])
        opcode = first_byte >> 2
        if opcode == 0:
            return Link_Open_Message
        elif opcode == 1:
            return Link_ACK_Message
        elif opcode == 2:
            return Link_Close_Message
        return Raw

    def do_dissect(self, s):
        s = Packet.do_dissect(self, s)
        cls = self._get_opcode_cls()
        if cls is not None:
            try:
                child = cls(s, _internal=1, _underlayer=self)
            except Exception:
                child = cls(_internal=1, _underlayer=self)
            self.add_payload(child)
            return b""
        return s

    def _get_opcode_cls(self):
        opcode = self.getfieldval("BearerOpcode")
        if opcode == 0:
            return Link_Open_Message
        if opcode == 1:
            return Link_ACK_Message
        if opcode == 2:
            return Link_Close_Message
        return None


class Link_Open_Message(Packet):
    name = "Link_Open_Message"
    fields_desc = [
        UUIDField("Device_UUID", None),
    ]


class Link_ACK_Message(Packet):
    name = "Link_ACK_Message"
    fields_desc = []

    def summary(self):
        return "Link ACK Message"


class Link_Close_Message(Packet):
    name = "Link_Close_Message"
    fields_desc = [
        ByteField("Reason", 0x00)
    ]


class BLEMesh_Provisioning_PDU(Packet):
    name = "BLEMesh_Provisioning_PDU"
    fields_desc = [
        BitField("PDU_Padding", 0, 2),
        BitEnumField("PDU_Type", 0, 6,
                     {0: "Provisioning Invite",
                      1: "Provisioning Capabilities",
                      2: "Provisioning Start",
                      3: "Provisioning Public Key",
                      4: "Provisioning Input Complete",
                      5: "Provisioning Confirmation",
                      6: "Provisioning Random",
                      7: "Provisioning Data",
                      8: "Provisioning Complete",
                      9: "Provisioning Failed",
                      }),
    ]


class Unseg_Control_Message(Packet):
    name = "Unsegmented_Control_Message"
    fields_desc = [
        BitField("SEG", 0, 1),
        BitField("Opcode", 0, 7)
    ]
    
    def guess_payload_class(self, payload):
        """根据 Opcode 选择正确的 payload 类"""
        # 优先使用已解析的 Opcode 字段
        opcode = None
        if hasattr(self, 'Opcode') and self.Opcode is not None:
            opcode = self.Opcode
        elif isinstance(payload, bytes) and len(payload) > 0:
            # 如果字段还未解析，从 payload 的第一个字节提取 Opcode
            # 注意：这里的 payload 是 Unseg_Control_Message 之后的剩余数据
            # 但 Opcode 已经在 Unseg_Control_Message 的第一个字节中解析了
            # 所以我们应该使用已解析的 Opcode 字段
            pass
        
        # 如果 Opcode 是 0x00，返回 SEG_ACK
        if opcode == 0x00:
            return SegmentAckPayload
        
        # 尝试使用 bind_layers 的机制
        result = Packet.guess_payload_class(self, payload)
        if result != conf.raw_layer:
            return result
        
        # 如果 bind_layers 没有找到匹配，但 Opcode 是 0x00，返回 SEG_ACK
        if opcode == 0x00:
            return SegmentAckPayload
        
        return result
    
    def extract_padding(self, s):
        """提取 padding，返回 payload 和 padding"""
        # 返回所有剩余数据作为 payload，让 guess_payload_class 来处理
        return s, b""


class Seg_Control_Message(Packet):
    name = "Segmented_Control_Message"
    fields_desc = [
        BitField("SEG", 0, 1),
        BitField("Opcode", 0, 7),
        BitField("RFU", 0, 1),
        BitField("SeqZero", 0, 13),
        BitField("SegO", 0, 5),
        BitField("SegN", 0, 5)
    ]




class SegmentAckPayload(Packet):
    """Segment Acknowledgment - Control Opcode 0x00"""
    name = "SEG_ACK"
    fields_desc = [
        BitField("OBO", 0, 1),
        BitField("SeqZero", 0, 13),
        BitField("RFU", 0, 2),
        IntField("BlockAck", 0),
    ]
    
    


class Control_Message(Packet):
    name = "Control_Message"
    fields_desc = [
        BitField("SEG", 0, 1),
        BitField("Opcode", 0, 7)
    ]


class Unseg_Access_Message(Packet):
    name = "Unsegmented_Access_Message"
    fields_desc = [
        BitField("SEG", 1, 1),
        BitField("AKF", 0, 1),
        BitField("AID", 0, 6)
    ]

    def do_dissect(self, s):
        """解析未分段访问层，并尝试解析模型层"""
        payload_bytes = Packet.do_dissect(self, s)
        if payload_bytes:
            model_pkt = parse_bluetooth_mesh_model_message(payload_bytes)
            if model_pkt is None:
                model_pkt = Raw(payload_bytes)
            self.add_payload(model_pkt)
        return b""
    
    def post_build(self, pkt, pay):
        # 确保 pkt 是 bytes 类型
        if isinstance(pkt, tuple):
            try:
                pkt = b''.join(x if isinstance(x, bytes) else bytes([x]) for x in pkt)
            except (TypeError, ValueError):
                pkt = b''
        elif not isinstance(pkt, bytes):
            try:
                pkt = bytes(pkt) if hasattr(pkt, '__iter__') else b''
            except (TypeError, ValueError):
                pkt = b''
        
        # 确保 pay 是 bytes 类型
        if not isinstance(pay, bytes):
            if isinstance(pay, tuple):
                try:
                    pay = b''.join(x if isinstance(x, bytes) else bytes([x]) for x in pay)
                except (TypeError, ValueError):
                    pay = b''
            else:
                try:
                    pay = bytes(pay) if hasattr(pay, '__iter__') else b''
                except (TypeError, ValueError):
                    pay = b''
        
        return pkt + pay


class Seg_Access_Message(Packet):
    name = "Segmented_Access_Message"
    fields_desc = [
        BitField("SEG", 1, 1),
        BitField("AKF", 0, 1),
        BitField("AID", 0, 6),
        BitField("SZMIC", 0, 1),
        BitField("SeqZero", 0, 13),
        BitField("SegO", 0, 5),
        BitField("SegN", 0, 5),
    ]
    



#####################
#  Model Layer      #
#####################

class ConfigCompositionDataStatus(Packet):
    name = "Config Composition Data Status"
    fields_desc = [
        ByteField("opcode", 0x02),
        ByteField("page", 0),
        StrLenField("data", b"")
    ]


class ConfigCompositionDataGet(Packet):
    name = "Config Composition Data Get"
    fields_desc = [
        ShortField("opcode", 0x8008),
        ByteField("page", 0)
    ]


class ConfigDefaultTTLGet(Packet):
    name = "Config Default TTL Get"
    fields_desc = [
        ShortField("opcode", 0x800C)
    ]


class ConfigDefaultTTLSet(Packet):
    name = "Config Default TTL Set"
    fields_desc = [
        ShortField("opcode", 0x800D),
        ByteField("ttl", 0)
    ]


class ConfigDefaultTTLStatus(Packet):
    name = "Config Default TTL Status"
    fields_desc = [
        ShortField("opcode", 0x800E),
        ByteField("ttl", 0)
    ]


class ConfigGATTProxyGet(Packet):
    name = "Config GATT Proxy Get"
    fields_desc = [
        ShortField("opcode", 0x8012)
    ]


class ConfigGATTProxySet(Packet):
    name = "Config GATT Proxy Set"
    fields_desc = [
        ShortField("opcode", 0x8013),
        ByteField("gatt_proxy", 0)
    ]


class ConfigGATTProxyStatus(Packet):
    name = "Config GATT Proxy Status"
    fields_desc = [
        ShortField("opcode", 0x8014),
        ByteField("gatt_proxy", 0)
    ]


class ConfigKeyRefreshPhaseGet(Packet):
    name = "Config Key Refresh Phase Get"
    fields_desc = [
        ShortField("opcode", 0x8015),
        ShortField("net_key_index", 0)
    ]


class ConfigKeyRefreshPhaseSet(Packet):
    name = "Config Key Refresh Phase Set"
    fields_desc = [
        ShortField("opcode", 0x8016),
        ShortField("net_key_index", 0),
        ByteField("transition", 0)
    ]


class ConfigKeyRefreshPhaseStatus(Packet):
    name = "Config Key Refresh Phase Status"
    fields_desc = [
        ShortField("opcode", 0x8017),
        ByteField("status", 0),
        ShortField("net_key_index", 0),
        ByteField("phase", 0)
    ]


class ConfigHeartbeatPublicationGet(Packet):
    name = "Config Heartbeat Publication Get"
    fields_desc = [
        ShortField("opcode", 0x8038)
    ]


class ConfigHeartbeatPublicationSet(Packet):
    name = "Config Heartbeat Publication Set"
    fields_desc = [
        ShortField("opcode", 0x8039),
        ShortField("destination", 0),
        ByteField("count_log", 0),
        ByteField("period_log", 0),
        ByteField("ttl", 0),
        ShortField("features", 0),
        ShortField("net_key_index", 0)
    ]


class ConfigHeartbeatPublicationStatus(Packet):
    name = "Config Heartbeat Publication Status"
    fields_desc = [
        ByteField("opcode", 0x06),
        ByteField("status", 0),
        ShortField("destination", 0),
        ByteField("count_log", 0),
        ByteField("period_log", 0),
        ByteField("ttl", 0),
        ShortField("features", 0),
        ShortField("net_key_index", 0)
    ]


class ConfigHeartbeatSubscriptionGet(Packet):
    name = "Config Heartbeat Subscription Get"
    fields_desc = [
        ShortField("opcode", 0x803A)
    ]


class ConfigHeartbeatSubscriptionSet(Packet):
    name = "Config Heartbeat Subscription Set"
    fields_desc = [
        ShortField("opcode", 0x803B),
        ShortField("source", 0),
        ShortField("destination", 0),
        ByteField("period_log", 0)
    ]


class ConfigHeartbeatSubscriptionStatus(Packet):
    name = "Config Heartbeat Subscription Status"
    fields_desc = [
        ShortField("opcode", 0x803C),
        ByteField("status", 0),
        ShortField("source", 0),
        ShortField("destination", 0),
        ByteField("period_log", 0),
        ByteField("count_log", 0),
        ByteField("min_hops", 0),
        ByteField("max_hops", 0)
    ]


class ConfigLowPowerNodePollTimeoutGet(Packet):
    name = "Config Low Power Node PollTimeout Get"
    fields_desc = [
        ShortField("opcode", 0x802D),
        ShortField("lpn_address", 0)
    ]


class ConfigModelSubscriptionAdd(Packet):
    name = "Config Model Subscription Add"
    fields_desc = [
        ShortField("opcode", 0x801B),
        ShortField("element_address", 0),
        ShortField("address", 0),  # Group address to add
        ShortField("model_identifier", 0)  # SIG Model ID (2 bytes)
    ]

class ConfigModelSubscriptionDelete(Packet):
    name = "Config Model Subscription Delete"
    fields_desc = [
        ShortField("opcode", 0x801C),
        ShortField("element_address", 0),
        ShortField("address", 0),  # Group address to delete
        ShortField("model_identifier", 0)  # SIG Model ID (2 bytes)
    ]


class ConfigNetworkKeyAdd(Packet):
    name = "Config Network Key Add"
    fields_desc = [
        ShortField("opcode", 0x8040),
        ShortField("net_key_index", 0),
        StrFixedLenField("net_key", b"\x11" * 16, 16)
    ]

class ConfigNetworkKeyUpdate(Packet):
    name = "Config Network Key Update"
    fields_desc = [
        ShortField("opcode", 0x8045),
        ShortField("net_key_index", 0),
        StrFixedLenField("net_key", b"\x01" * 16, 16)
    ]

class ConfigNetworkKeyDelete(Packet):
    name = "Config Network Key Delete"
    fields_desc = [
        ShortField("opcode", 0x8041),
        ShortField("net_key_index", 0)
    ]

class ConfigNetworkKeyStatus(Packet):
    name = "Config Network Key Status"
    fields_desc = [
        ShortField("opcode", 0x8044),
        ByteField("status", 0),
        ShortField("net_key_index", 0)
    ]

class ConfigNetworkKeyGet(Packet):
    name = "Config Network Key Get"
    fields_desc = [
        ShortField("opcode", 0x8042),
    ]

class ConfigNetworkKeyList(Packet):
    name = "Config Network Key List"
    fields_desc = [
        ShortField("opcode", 0x8043),
        # 打包的 NetKey 索引列表(每个索引12 bits)
        StrLenField("net_key_indexes", b"")  # 需要特殊的解包逻辑
    ]

class ConfigAppKeyAdd(Packet):
    name = "Config App Key Add"
    fields_desc = [
        ByteField("opcode", 0x00),
        BitField("net_key_index", 0, 12),
        BitField("app_key_index", 0, 12),
        StrFixedLenField("app_key", b"\x00" * 16, 16)
    ]
    
class ConfigAppKeyUpdate(Packet):
    name = "Config App Key Update"
    fields_desc = [
        ByteField("opcode", 0x01),
        BitField("net_key_index", 0, 12),
        BitField("app_key_index", 0, 12),
        StrFixedLenField("app_key", b"\x00" * 16, 16)
    ]


class ConfigAppKeyDelete(Packet):
    name = "Config App Key Delete"
    fields_desc = [
        ShortField("opcode", 0x8000),
        BitField("net_key_index", 0, 12),
        BitField("app_key_index", 0, 12)        
    ]


class ConfigAppKeyGet(Packet):
    name = "Config App Key Get"
    fields_desc = [
        ShortField("opcode", 0x8001),
        ShortField("net_key_index", 0)
    ]


class ConfigAppKeyList(Packet):
    name = "Config App Key List"
    fields_desc = [
        ShortField("opcode", 0x8002),
        ByteField("status", 0),
        ShortField("net_key_index", 0),
        StrLenField("app_key_indexes", b"")
    ]


class ConfigAppKeyStatus(Packet):
    name = "Config App Key Status"
    fields_desc = [
        ShortField("opcode", 0x8003),
        ByteField("status", 0),
        X3BytesField("packed_indexes", 0)  # 包含 NetKeyIndex 和 AppKeyIndex
    ]


class ConfigBeaconGet(Packet):
    name = "Config Beacon Get"
    fields_desc = [
        ShortField("opcode", 0x8009)
    ]


class ConfigBeaconSet(Packet):
    name = "Config Beacon Set"
    fields_desc = [
        ShortField("opcode", 0x800A),
        ByteField("beacon", 0)
    ]


class ConfigBeaconStatus(Packet):
    name = "Config Beacon Status"
    fields_desc = [
        ShortField("opcode", 0x800B),
        ByteField("beacon", 0)
    ]


class ConfigFriendGet(Packet):
    name = "Config Friend Get"
    fields_desc = [
        ShortField("opcode", 0x800F)
    ]


class ConfigFriendSet(Packet):
    name = "Config Friend Set"
    fields_desc = [
        ShortField("opcode", 0x8010),
        ByteField("friend", 0)  # 0x00 = Disable, 0x01 = Enable, 0x02 = Not supported
    ]


class ConfigFriendStatus(Packet):
    name = "Config Friend Status"
    fields_desc = [
        ShortField("opcode", 0x8011),
        ByteField("status", 0),  # Status for the requesting message
        ByteField("friend", 0)   # Current Friend feature state
    ]


class ConfigRelayGet(Packet):
    name = "Config Relay Get"
    fields_desc = [
        ShortField("opcode", 0x8026)
    ]


class ConfigRelaySet(Packet):
    name = "Config Relay Set"
    fields_desc = [
        ShortField("opcode", 0x8027),
        ByteField("relay", 0),
        ByteField("relay_retransmit_count", 0),
        ByteField("relay_retransmit_interval_steps", 0)
    ]


class ConfigRelayStatus(Packet):
    name = "Config Relay Status"
    fields_desc = [
        ShortField("opcode", 0x8028),
        ByteField("relay", 0),
        ByteField("relay_retransmit_count", 0),
        ByteField("relay_retransmit_interval_steps", 0)
    ]


class ConfigSIGModelSubscriptionGet(Packet):
    name = "Config SIG Model Subscription Get"
    fields_desc = [
        ShortField("opcode", 0x8029),
        ShortField("element_address", 0),
        ShortField("model_id", 0)
    ]


class ConfigNodeIdentityGet(Packet):
    name = "Config Node Identity Get"
    fields_desc = [
        ShortField("opcode", 0x8046),
        ShortField("net_key_index", 0)
    ]


class ConfigNodeIdentitySet(Packet):
    name = "Config Node Identity Set"
    fields_desc = [
        ShortField("opcode", 0x8047),
        ShortField("net_key_index", 0),
        ByteField("identity", 0)
    ]


class ConfigNodeIdentityStatus(Packet):
    name = "Config Node Identity Status"
    fields_desc = [
        ShortField("opcode", 0x8048),
        ByteField("status", 0),
        ShortField("net_key_index", 0),
        ByteField("identity", 0)
    ]


class ConfigNodeReset(Packet):
    name = "Config Node Reset"
    fields_desc = [
        ShortField("opcode", 0x8049)
    ]


class ConfigNodeResetStatus(Packet):
    name = "Config Node Reset Status"
    fields_desc = [
        ShortField("opcode", 0x804A)
    ]


class ConfigSIGModelAppGet(Packet):
    name = "Config SIG Model App Get"
    fields_desc = [
        ShortField("opcode", 0x804B),
        ShortField("element_address", 0),
        ShortField("model_id", 0)
    ]


class ConfigSIGModelAppList(Packet):
    name = "Config SIG Model App List"
    fields_desc = [
        ShortField("opcode", 0x804C),
        ByteField("status", 0),
        ShortField("element_address", 0),
        ShortField("model_id", 0),
        StrLenField("app_key_indexes", b"")
    ]


class ConfigModelAppBind(Packet):
    name = "Config Model App Bind"
    fields_desc = [
        ShortField("opcode", 0x803D),
        ShortField("element_address", 0),
        ShortField("app_key_index", 0),
        # ModelIdentifier: 2 bytes for SIG Model, 4 bytes for Vendor Model
        ShortField("model_identifier", 0)  # SIG Model ID (2 bytes)
    ]


class ConfigModelAppUnbind(Packet):
    name = "Config Model App Unbind"
    fields_desc = [
        ShortField("opcode", 0x803F),
        ShortField("element_address", 0),
        ShortField("app_key_index", 0),
        # ModelIdentifier: 2 bytes for SIG Model, 4 bytes for Vendor Model
        ShortField("model_identifier", 0) 
    ]


class ConfigModelAppStatus(Packet):
    name = "Config Model App Status"
    fields_desc = [
        ShortField("opcode", 0x803E),
        ByteField("status", 0),
        ShortField("element_address", 0),
        ShortField("app_key_index", 0),
        # ModelIdentifier: 2 bytes for SIG Model, 4 bytes for Vendor Model
        ShortField("model_identifier", 0)
    ]


#####################
# Upper Transport Control Messages #
#####################

class Heartbeat(Packet):
    name = "Heartbeat"
    fields_desc = [
        BitField("RFU", 0, 1),
        BitField("InitTTL", 0, 7),
        LEShortField("Features", 0)
    ]


class Friend_Poll(Packet):
    name = "Friend_Poll"
    fields_desc = [
        BitField("Padding", 0, 7),
        BitField("FSN", 0, 1),
    ]


class Friend_Update(Packet):
    name = "Friend_Update"
    fields_desc = [
        ByteField("Flags", 0),
        LEIntField("IVIndex", 0),
        LEShortField("MD", 0),
    ]


class Friend_Request(Packet):
    name = "Friend_Request"
    fields_desc = [
        ByteField("Criteria", 0),
        ByteField("ReceiveDelay", 0),
        X3BytesField("PollTimeout", 0),
        LEShortField("PreviousAddress", 0),
        ByteField("NumElements", 0),
        LEShortField("LPNCounter", 0)
    ]


class Friend_Offer(Packet):
    name = "Friend_Offer"
    fields_desc = [
        ByteField("Flags", 0),
        LEIntField("IVIndex", 0),
        LEShortField("MD", 0),
    ]


class Friend_Clear(Packet):
    name = "Friend_Clear"
    fields_desc = [
        LEShortField("LPNAddress", 0),
        LEShortField("LPNCounter", 0),
    ]


class Friend_Clear_Confirm(Packet):
    name = "Friend_Clear_Confirm"
    fields_desc = [
        LEShortField("LPNAddress", 0),
        LEShortField("LPNCounter", 0)
    ]


class Friend_Subscription_List_Add(Packet):
    name = "Friend_Subscription_List_Add"
    fields_desc = [
        ByteField("TransactionNumber", 0),
        StrLenField("AddressList", None)
    ]


class Friend_Subscription_List_Remove(Packet):
    name = "Friend_Subscription_List_Remove"
    fields_desc = [
        ByteField("TransactionNumber", 0),
        StrLenField("AddressList", None)
    ]


class Friend_Subscription_List_Confirm(Packet):
    name = "Friend_Subscription_List_Confirm"
    fields_desc = [
        ByteField("TransactionNumber", 0)
    ]


#####################
# Generic Model Messages #
#####################

class GenericOnOffGet(Packet):
    name = "Generic OnOff Get"
    fields_desc = [
        ShortField("opcode", 0x8201)
    ]


class GenericOnOffSet(Packet):
    name = "Generic OnOff Set"
    fields_desc = [
        ShortField("opcode", 0x8202),
        ByteField("on_off", 0),
        ByteField("tid", 0),
        ByteField("transition_time", 0),
        ByteField("delay", 0)
    ]


class GenericOnOffSetUnacknowledged(Packet):
    name = "Generic OnOff Set Unacknowledged"
    fields_desc = [
        ShortField("opcode", 0x8203),
        ByteField("on_off", 0),
        ByteField("tid", 0),
        ByteField("transition_time", 0),
        ByteField("delay", 0)
    ]


class GenericOnOffStatus(Packet):
    name = "Generic OnOff Status"
    fields_desc = [
        ShortField("opcode", 0x8204),
        ByteField("present_on_off", 0),
        ByteField("target_on_off", 0),
        ByteField("remaining_time", 0)
    ]


class GenericModelMessage(Packet):
    """通用模型层消息，用于未识别的消息类型"""
    name = "Generic Model Message"
    fields_desc = [
        StrLenField("opcode", b""),
        StrLenField("parameters", b"")
    ]


class Message_Decode(Packet):
    name = "BLEMesh Message Decode"

    fields_desc = [
        BitField("IVI", 0, 1),
        BitField("NID", 0, 7),
        BitEnumField("CTL", 0, 1, {0: "Access Message and NetMIC 32bit", 1: "Control Message and NetMIC_64bit"}),
        BitField("TTL", 0, 7),
        ThreeBytesField("SEQ", 20),
        ShortField("SRC", 0),
        ShortField("DST", 0),
        # 使用 StrLenField 捕获剩余的所有数据（Transport + NetMIC）
        # 这个字段会被 post_dissect 处理，不会直接显示
        # StrLenField("_remaining", b"", length_from=lambda pkt: 0),
        # NetMIC 字段需要手动处理，因为它不在固定位置
    ]

    def guess_payload_class(self, payload):
        """根据 CTL 和 SEG 位选择下层"""
        if not payload:
            return Packet.guess_payload_class(self, payload)
        first_byte = payload[0] if isinstance(payload[0], int) else ord(payload[0])
        seg = (first_byte >> 7) & 0x1
        if self.CTL == 0:
            return Seg_Access_Message if seg else Unseg_Access_Message
        else:
            return Seg_Control_Message if seg else Unseg_Control_Message

    def post_build(self, p, pay):
        # 确保 p 是 bytes 类型
        if isinstance(p, tuple):
            # 如果 p 是 tuple，尝试将 tuple 中的元素连接成 bytes
            try:
                p = b''.join(x if isinstance(x, bytes) else bytes([x]) for x in p)
            except (TypeError, ValueError):
                # 如果转换失败，使用空 bytes
                p = b''
        elif not isinstance(p, bytes):
            # 如果不是 bytes 也不是 tuple，尝试转换
            try:
                if isinstance(p, (list, tuple)):
                    p = b''.join(x if isinstance(x, bytes) else bytes([x]) for x in p)
                else:
                    p = bytes(p)
            except (TypeError, ValueError):
                p = b''
        
        # 确保 pay 是 bytes 类型
        if not isinstance(pay, bytes):
            if isinstance(pay, tuple):
                try:
                    pay = b''.join(x if isinstance(x, bytes) else bytes([x]) for x in pay)
                except (TypeError, ValueError):
                    pay = b''
            else:
                try:
                    pay = bytes(pay) if hasattr(pay, '__iter__') else b''
                except (TypeError, ValueError):
                    pay = b''
        
        mic_bits = 32 if self.CTL == 0 else 64
        mic_bytes = mic_bits // 8

        # 当我们是"解析后的包"并且保存了 NetMIC 字段时，需要把 payload 插入 NetMIC 之前
        has_netmic = (
            hasattr(self, "NetMIC_32") or hasattr(self, "NetMIC_64")
        )
        if has_netmic and len(p) >= mic_bytes:
            netmic = p[-mic_bytes:]
            return p[:-mic_bytes] + pay + netmic

        # 对于构造发送的包（尚未计算 NetMIC），直接附加 payload
        return p + pay

    def post_dissect(self, p):
        """解析网络层后的 Transport + Access/Control 负载"""
        if p is None or len(p) == 0:
            return b""

        # 对于构造的包（用于发送），通常不包含 NetMIC
        # 对于接收/解析的包，NetMIC 在最后
        # 我们需要判断：如果数据太短（只够 NetMIC），说明这是构造的包，没有 NetMIC
        netmic_len = 4 if self.CTL == 0 else 8
        
        # 只有当之前已经解析并保存了 NetMIC 字段时，才认为当前数据包含 NetMIC
        has_netmic = (
            hasattr(self, "NetMIC_32") or hasattr(self, "NetMIC_64")
        ) and len(p) > netmic_len
        
        if has_netmic:
            netmic_bytes = p[-netmic_len:]
            payload = p[:-netmic_len]
            # 保存 NetMIC 字段
            if self.CTL == 0:
                self.NetMIC_32 = netmic_bytes
            else:
                self.NetMIC_64 = netmic_bytes
        else:
            # 没有 NetMIC，所有数据都是 payload
            payload = p

        if payload:
            if self.CTL == 0:  # 访问层
                self._parse_access_message(payload)
            else:  # 控制层
                self._parse_control_message(payload)
            # 返回 payload 数据，让 Scapy 通过 guess_payload_class 自动解析子层
            return payload

        return b""

    def _parse_access_message(self, payload):
        """解析访问层消息"""
        if len(payload) < 1:
            return

        # 解析访问层头部
        seg = (payload[0] >> 7) & 0x1
        akf = (payload[0] >> 6) & 0x1
        aid = payload[0] & 0x3F

        self.access_info = {
            'SEG': seg,
            'AKF': akf,
            'AID': aid,
            'is_segmented': seg == 1
        }

        if seg == 1 and len(payload) >= 3:  # 分段消息
            szmic = (payload[1] >> 7) & 0x1
            seq_zero = payload[1] & 0x7F
            seg_o = payload[2] & 0x1F
            seg_n = (payload[2] >> 5) & 0x1F

            self.access_info.update({
                'SZMIC': szmic,
                'SeqZero': seq_zero,
                'SegO': seg_o,
                'SegN': seg_n
            })

            # 应用层数据从第4字节开始（分段消息头部占3字节）
            if len(payload) > 3:
                app_data = payload[3:]
            else:
                app_data = b""
            self.application_data = app_data
            if app_data:
                self._parse_model_layer(app_data)
        else:  # 非分段消息
            # 应用层数据从第2字节开始（头部占1字节）
            if len(payload) > 1:
                app_data = payload[1:]
            else:
                app_data = b""
            self.application_data = app_data
            if app_data:
                self._parse_model_layer(app_data)

    def _parse_control_message(self, payload):
        """解析控制层消息"""
        if len(payload) < 1:
            return

        # 解析控制层头部
        seg = (payload[0] >> 7) & 0x1
        opcode = payload[0] & 0x7F

        self.control_info = {
            'SEG': seg,
            'Opcode': opcode,
            'is_segmented': seg == 1
        }

        if seg == 1 and len(payload) >= 3:  # 分段消息
            rfu = (payload[1] >> 7) & 0x1
            seq_zero = payload[1] & 0x7F
            seg_o = payload[2] & 0x1F
            seg_n = (payload[2] >> 5) & 0x1F

            self.control_info.update({
                'RFU': rfu,
                'SeqZero': seq_zero,
                'SegO': seg_o,
                'SegN': seg_n
            })

            # 控制参数从第4字节开始
            if len(payload) > 3:
                self.control_params = payload[3:]
        else:  # 非分段消息
            # 控制参数从第2字节开始
            if len(payload) > 1:
                self.control_params = payload[1:]

    def _parse_model_layer(self, data):
        """解析模型层消息"""
        if len(data) < 1:
            return

        # 首先尝试基本Opcode识别
        self._parse_basic_opcode(data)

        # 如果识别为Config Composition Data Status，直接使用基本解析
        if hasattr(self, 'model_info') and 'opcode' in self.model_info:
            opcode = self.model_info['opcode']
            if opcode == 0x02:  # Config Composition Data Status
                return

        # 对于其他消息，尝试使用 ble_mesh.py 中的解析函数
        try:
            model_packet = parse_bluetooth_mesh_model_message(data)
            if model_packet is not None:
                self.model_layer = model_packet
                self.model_info = {
                    'type': model_packet.__class__.__name__,
                    'parsed': True
                }
        except Exception as e:
            # 解析失败，保持基本解析结果
            pass

    def _parse_basic_opcode(self, data):
        """基本Opcode解析，当完整解析失败时使用"""
        if len(data) < 1:
            return


        # 解析Opcode
        if data[0] & 0x80 == 0:  # 1字节Opcode
            opcode = data[0]
            opcode_len = 1
        elif data[0] & 0x40 == 0:  # 2字节Opcode
            if len(data) >= 2:
                opcode = int.from_bytes(data[0:2], 'big')
                opcode_len = 2
            else:
                return
        else:  # 3字节Opcode
            if len(data) >= 3:
                opcode = int.from_bytes(data[0:3], 'big')
                opcode_len = 3
            else:
                return


        self.model_info = {
            'type': 'Unknown Model Message',
            'opcode': opcode,
            'opcode_len': opcode_len,
            'parsed': False,
            'raw_data': data
        }

        # 尝试识别常见的Opcode（仅用于人类可读的类型名）
        opcode_names = {
            0x02:   'Config Composition Data Status',
            0x8008: 'Config Composition Data Get',

            0x8009: 'Config Beacon Get',
            0x800A: 'Config Beacon Set',
            0x800B: 'Config Beacon Status',

            0x800C: 'Config Default TTL Get',
            0x800D: 'Config Default TTL Set',
            0x800E: 'Config Default TTL Status',

            0x800F: 'Config Friend Get',
            0x8010: 'Config Friend Set',
            0x8011: 'Config Friend Status',

            0x8012: 'Config GATT Proxy Get',
            0x8013: 'Config GATT Proxy Set',
            0x8014: 'Config GATT Proxy Status',

            0x00:   'Config App Key Add',
            0x01:   'Config App Key Update',
            0x8000: 'Config App Key Delete',
            0x8001: 'Config App Key Get',
            0x8002: 'Config App Key List',
            0x8003: 'Config App Key Status',

            0x8040: 'Config NetKey Add',
            0x8041: 'Config NetKey Delete',
            0x8042: 'Config NetKey Get',
            0x8043: 'Config NetKey List',
            0x8044: 'Config NetKey Status',
            0x8045: 'Config NetKey Update',

            0x8201: 'Generic OnOff Get',
            0x8202: 'Generic OnOff Set',
            0x8203: 'Generic OnOff Set Unacknowledged',
            0x8204: 'Generic OnOff Status',
        }

        if opcode in opcode_names:
            self.model_info['type'] = opcode_names[opcode]

    def show_parsed_info(self):
        """显示解析后的详细信息"""
        print("=== BLE Mesh 消息解析结果 ===")
        print(f"网络层信息:")
        print(f"  IVI: {self.IVI}")
        print(f"  NID: {self.NID}")
        print(f"  CTL: {self.CTL} ({'Access Message' if self.CTL == 0 else 'Control Message'})")
        print(f"  TTL: {self.TTL}")
        print(f"  SEQ: {self.SEQ}")
        print(f"  SRC: {self.SRC} (0x{self.SRC:04x})")
        print(f"  DST: {self.DST} (0x{self.DST:04x})")

        if self.CTL == 0:
            print(f"  NetMIC (32位): 0x{self.NetMIC_32:08x}")
        else:
            print(f"  NetMIC (64位): 0x{self.NetMIC_64:016x}")

        if hasattr(self, 'access_info'):
            print(f"\n访问层信息:")
            print(f"  SEG: {self.access_info['SEG']} ({'分段消息' if self.access_info['is_segmented'] else '非分段消息'})")
            print(f"  AKF: {self.access_info['AKF']}")
            print(f"  AID: {self.access_info['AID']}")

            if self.access_info['is_segmented']:
                print(f"  SZMIC: {self.access_info.get('SZMIC', 'N/A')}")
                print(f"  SeqZero: {self.access_info.get('SeqZero', 'N/A')}")
                print(f"  SegO: {self.access_info.get('SegO', 'N/A')}")
                print(f"  SegN: {self.access_info.get('SegN', 'N/A')}")

            if hasattr(self, 'application_data'):
                print(f"\n应用层数据:")
                print(f"  长度: {len(self.application_data)} 字节")
                print(f"  十六进制: {self.application_data.hex()}")

        # 显示模型层信息
        if hasattr(self, 'model_info'):
            print(f"\n模型层信息:")
            print(f"  消息类型: {self.model_info['type']}")
            if 'opcode' in self.model_info:
                print(f"  Opcode: 0x{self.model_info['opcode']:04x} ({self.model_info['opcode']})")
                print(f"  Opcode长度: {self.model_info['opcode_len']} 字节")
            print(f"  解析状态: {'成功' if self.model_info['parsed'] else '基本识别'}")

            # 如果成功解析了模型层数据包，显示详细信息
            if hasattr(self, 'model_layer') and self.model_layer is not None:
                print(f"\n模型层详细信息:")
                self.model_layer.show()

    def show(self, dump=False, indent=3, lvl="", label_lvl=""):
        """保持与 Scapy 默认 show 行为一致"""
        return super().show(dump, indent, lvl, label_lvl)

    def mysummary(self):
        """返回 Message_Decode 的简单名称"""
        return "Message_Decode"
    
    def _do_summary(self):
        """重写 _do_summary 方法，确保正确递归显示所有子层"""
        # 首先获取 payload 的 summary
        found, s, needed = 0, "", []
        if self.payload and self.payload.__class__.__name__ not in ["NoPayload"]:
            found, s, needed = self.payload._do_summary()
        
        # 获取当前层的 mysummary
        ret = ""
        if not found or self.__class__ in needed:
            ret = self.mysummary()
            if isinstance(ret, tuple):
                ret, n = ret
                needed += n
        if ret or needed:
            found = 1
        if not ret:
            ret = self.__class__.__name__
        
        # 连接 payload 的 summary
        if ret and s:
            ret = "%s / %s" % (ret, s)
        else:
            ret = "%s%s" % (ret, s)
        
        return found, ret, needed

    def _get_opcode_name(self, opcode):
        """获取Opcode的名称"""
        opcode_names = {
            0x02: "Config Composition Data Status",
            0x8008: "Config Composition Data Get",
            0x8009: "Config Beacon Get",
            0x800A: "Config Beacon Set",
            0x800B: "Config Beacon Status",
            0x800C: "Config Default TTL Get",
            0x800D: "Config Default TTL Set",
            0x800E: "Config Default TTL Status",
            0x8012: "Config GATT Proxy Get",
            0x8013: "Config GATT Proxy Set",
            0x8014: "Config GATT Proxy Status",
            0x00: "Config App Key Add",
            0x8000: "Config App Key Delete",
            0x8001: "Config App Key Get",
            0x8002: "Config App Key List",
            0x8003: "Config App Key Status",
            0x8201: "Generic OnOff Get",
            0x8202: "Generic OnOff Set",
            0x8203: "Generic OnOff Set Unacknowledged",
            0x8204: "Generic OnOff Status",
        }
        return opcode_names.get(opcode, "Unknown Message")

    def _show_model_layer_details(self):
        """显示详细的模型层信息"""
        if not hasattr(self, 'model_layer') or self.model_layer is None:
            return

        print("\n###[ Model Layer Details ]###")

        # 特殊处理Config Composition Data Status消息
        if hasattr(self.model_layer,
                   '__class__') and 'ConfigCompositionDataStatus' in self.model_layer.__class__.__name__:
            self._show_composition_data_status()
        else:
            # 显示其他类型的模型层字段
            for field in self.model_layer.fields_desc:
                field_name = field.name
                if hasattr(self.model_layer, field_name):
                    field_value = getattr(self.model_layer, field_name)
                    if isinstance(field_value, bytes):
                        print(f"  {field_name:<20} = {field_value.hex()}")
                    else:
                        print(f"  {field_name:<20} = {field_value}")

    def _show_composition_data_status(self):
        """显示Config Composition Data Status的详细信息"""
        if not hasattr(self, 'model_layer'):
            return

        model = self.model_layer

        # 显示基本字段
        if hasattr(model, 'opcode'):
            opcode_name = self._get_opcode_name(model.opcode)
            print(f"  Opcode   = {opcode_name} (0x{model.opcode:04x})")

        if hasattr(model, 'page'):
            print(f"  Page     = 0x{model.page:02x}")

        # 解析composition data字段
        if hasattr(model, 'data') and model.data:
            data = model.data
            if len(data) >= 10:  # 基本composition data长度
                # CID (Company ID) - 2字节
                cid = int.from_bytes(data[0:2], 'little')
                cid_name = self._get_company_name(cid)
                print(f"  CID      = {cid_name} (0x{cid:04x})")

                # PID (Product ID) - 2字节
                pid = int.from_bytes(data[2:4], 'little')
                print(f"  PID      = {pid} (0x{pid:04x})")

                # VID (Version ID) - 2字节
                vid = int.from_bytes(data[4:6], 'little')
                print(f"  VID      = {vid} (0x{vid:04x})")

                # CRPL (Composition Replay Protection List) - 2字节
                crpl = int.from_bytes(data[6:8], 'little')
                print(f"  CRPL     = {crpl} (0x{crpl:04x})")

                # Features - 2字节
                if len(data) >= 10:
                    features = int.from_bytes(data[8:10], 'little')
                    print(f"  > Features = 0x{features:04x}")

                    # 解析Features位字段
                    self._show_features_details(features)

                # 如果有更多数据，显示Element信息
                if len(data) > 10:
                    print(f"  > Element #1")

    def _get_company_name(self, cid):
        """获取公司ID对应的公司名称"""
        company_names = {
            0x02E5: "Espressif Incorporated",
            0x0006: "Bluetooth SIG",
            0x004C: "Apple Inc.",
            0x00E0: "Google Inc.",
            0x0059: "Nordic Semiconductor ASA",
        }
        return company_names.get(cid, f"Unknown Company")

    def _show_features_details(self, features):
        """显示Features字段的详细信息"""
        feature_flags = []
        if features & 0x0001:
            feature_flags.append("Relay")
        if features & 0x0002:
            feature_flags.append("Proxy")
        if features & 0x0004:
            feature_flags.append("Friend")
        if features & 0x0008:
            feature_flags.append("Low Power")

        if feature_flags:
            print(f"    Features enabled: {', '.join(feature_flags)}")

    def _show_basic_model_info(self):
        """显示基本的模型层信息"""
        if not hasattr(self, 'application_data'):
            return

        data = self.application_data
        if len(data) < 1:
            return

        # 尝试解析Opcode
        opcode = data[0]
        if opcode & 0x80 == 0:  # 1字节Opcode
            opcode_name = self._get_opcode_name(opcode)
            print(f"  Opcode   = {opcode_name} (0x{opcode:04x})")

            # 如果是Config Composition Data Status (0x02)
            if opcode == 0x02 and len(data) >= 12:
                print(f"  Page     = 0x{data[1]:02x}")

                # 解析composition data
                if len(data) >= 12:
                    cid = int.from_bytes(data[2:4], 'little')
                    cid_name = self._get_company_name(cid)
                    print(f"  CID      = {cid_name} (0x{cid:04x})")

                    pid = int.from_bytes(data[4:6], 'little')
                    print(f"  PID      = {pid} (0x{pid:04x})")

                    vid = int.from_bytes(data[6:8], 'little')
                    print(f"  VID      = {vid} (0x{vid:04x})")

                    crpl = int.from_bytes(data[8:10], 'little')
                    print(f"  CRPL     = {crpl} (0x{crpl:04x})")

                    features = int.from_bytes(data[10:12], 'little')
                    print(f"  > Features = 0x{features:04x}")
                    self._show_features_details(features)

                    # 如果有更多数据，显示Element信息
                    if len(data) > 12:
                        print(f"  > Element #1")
    
    def _attach_transport_layer(self, payload, is_control=False):
        """将 Transport PDU 作为 Packet 挂载到 dissector 树"""
        if not payload:
            return
        first_byte = payload[0] if isinstance(payload[0], int) else payload[0]
        seg = (first_byte >> 7) & 0x1
        if is_control:
            cls = Seg_Control_Message if seg else Unseg_Control_Message
        else:
            cls = Seg_Access_Message if seg else Unseg_Access_Message
        try:
            child = cls(payload, _internal=1, _underlayer=self)
        except Exception:
            child = Raw(payload)
        self.add_payload(child)

class EncryptedNetworkPDU(Packet):
    """加密后的网络 PDU，用于包装已加密和混淆的 BLE Mesh 网络层数据"""
    name = "EncryptedNetworkPDU"
    
    fields_desc = [
        StrLenField("data", None)
    ]
    
    def __init__(self, _pkt=None, **kwargs):
        # 如果传入的是字节串，直接作为 data 字段
        if isinstance(_pkt, bytes):
            kwargs["data"] = _pkt
            _pkt = None
        elif _pkt is not None and not isinstance(_pkt, Packet):
            # 如果传入的是其他类型的数据，也尝试转换为字节串
            try:
                kwargs["data"] = bytes(_pkt)
                _pkt = None
            except:
                pass
        super().__init__(_pkt, **kwargs)
    
    def summary(self, intern=0):
        """返回加密网络 PDU 的摘要信息"""
        # 返回简单的类名，与第一个 summary 保持一致
        return "Encrypted_BLE_Mesh_Message"
    
    def show(self, dump=False, indent=3, lvl="", label_lvl=""):
        """显示加密网络 PDU 的详细信息，使用 scapy 标准格式"""
        # 调用父类的 show 方法以使用标准格式
        return super().show(dump=dump, indent=indent, lvl=lvl, label_lvl=label_lvl)


class BLEMesh_Message(Packet):
    name = "BLEMesh_Message"

    fields_desc = [BitField("IVI", 0, 1),
                   BitField("NID", 0, 7),
                   StrFixedLenField("Obfuscated", b'\x00' * 16, 16),
                   StrLenField("Encrypted_data_NetMIC", b'')
                   ]

    def summary(self, intern=0):
        """返回 BLE Mesh 层的摘要信息"""
        # 返回简单的类名，与第一个 summary 保持一致
        s = "BLEMesh_Message"
        if not intern and self.payload and self.payload.__class__.__name__ not in ["NoPayload", "Padding", "Raw", "None"]:
            try:
                s += " / " + self.payload.summary(intern=1)
            except:
                pass
        return s

    def show(self, dump=False, indent=3, lvl="", label_lvl=""):
        """显示 BLE Mesh 层的详细信息，使用 scapy 标准格式"""
        # 调用父类的 show 方法以使用标准格式
        return super().show(dump=dump, indent=indent, lvl=lvl, label_lvl=label_lvl)


class BLEMesh_Beacon(Packet):
    name = "BLEMesh_Beacon"

    fields_desc = [
        ByteEnumField("Beacon_Type", 0, {0: "Unprovisioned Device Beacon", 1: "Secure Network Beacon", 2: "Mesh Private Beacon"}),
    ]

    def do_dissect_payload(self, s):
        """重写 do_dissect_payload 以确保正确解析子类"""
        if s:
            # 获取 Beacon_Type 值
            beacon_type = self.fields.get('Beacon_Type')
            if beacon_type is None:
                beacon_type = self.getfieldval('Beacon_Type')
            
            # 根据 Beacon_Type 选择对应的子类
            if beacon_type == 0:
                cls = BLEMesh_Unprovisioned_Device_Beacon
            elif beacon_type == 1:
                cls = BLEMesh_Secure_Network_Beacon
            elif beacon_type == 2:
                cls = BLEMesh_Mesh_Private_Beacon
            else:
                # 使用默认的 guess_payload_class
                cls = self.guess_payload_class(s)
            
            try:
                # 创建子类实例时，将 Beacon_Type 作为关键字参数传递
                # 这样子类就不需要从数据中解析 Beacon_Type 了
                p = cls(s, _internal=1, _underlayer=self, Beacon_Type=beacon_type)
            except KeyboardInterrupt:
                raise
            except Exception:
                from scapy import config
                from scapy.error import log_runtime
                if config.conf.debug_dissector:
                    if issubtype(cls, Packet):
                        log_runtime.error("%s dissector failed", cls.__name__)
                    else:
                        log_runtime.error("%s.guess_payload_class() returned [%s]",
                                          self.__class__.__name__, repr(cls))
                    if cls is not None:
                        raise
                p = config.conf.raw_layer(s, _internal=1, _underlayer=self)
            self.add_payload(p)

    def guess_payload_class(self, payload):
        """根据 Beacon_Type 字段返回对应的子类"""
        # 在 do_dissect_payload 调用时，Beacon_Type 已经被解析到 self.fields 中
        # 首先尝试从 fields 字典获取（这是最可靠的方式）
        beacon_type = self.fields.get('Beacon_Type')
        
        # 如果 fields 中没有，尝试使用 getfieldval
        if beacon_type is None:
            beacon_type = self.getfieldval('Beacon_Type')
        
        # 如果还是 None，尝试从 raw_packet_cache 读取第一个字节
        if beacon_type is None:
            if hasattr(self, 'raw_packet_cache') and self.raw_packet_cache:
                if len(self.raw_packet_cache) > 0:
                    beacon_type = self.raw_packet_cache[0]
        
        # 根据 Beacon_Type 返回对应的子类
        # 注意：beacon_type 可能是 0（Unprovisioned Device Beacon），这是有效的值
        if beacon_type == 0:
            return BLEMesh_Unprovisioned_Device_Beacon
        elif beacon_type == 1:
            return BLEMesh_Secure_Network_Beacon
        elif beacon_type == 2:
            return BLEMesh_Mesh_Private_Beacon
        
        # 如果 beacon_type 不是 0/1/2，先尝试使用 bind_layers 的默认机制
        result = Packet.guess_payload_class(self, payload)
        # 如果默认机制返回了原始类，而我们确实有 beacon_type，返回对应的子类
        if result == self.__class__ and beacon_type is not None:
            # 默认返回 Unprovisioned Device Beacon
            return BLEMesh_Unprovisioned_Device_Beacon
        return result

    def _do_summary(self):
        """重写 _do_summary，当有子类时跳过父类"""
        # 如果有子类 payload，直接返回子类的 summary
        if self.payload and self.payload.__class__.__name__ in [
            "BLEMesh_Unprovisioned_Device_Beacon", 
            "BLEMesh_Secure_Network_Beacon", 
            "BLEMesh_Mesh_Private_Beacon"
        ]:
            # 直接使用子类的 _do_summary，跳过父类
            return self.payload._do_summary()
        
        # 否则使用标准的 _do_summary
        return Packet._do_summary(self)

    def show(self, dump=False, indent=3, lvl="", label_lvl=""):
        """显示 BLE Mesh Beacon 层的详细信息，使用 scapy 标准格式"""
        # 调用父类的 show 方法以使用标准格式
        return super().show(dump=dump, indent=indent, lvl=lvl, label_lvl=label_lvl)


class BLEMesh_Unprovisioned_Device_Beacon(BLEMesh_Beacon):
    name = "BLEMesh Unprovisioned Device Beacon"

    fields_desc = [
        # 注意：Beacon_Type 字段在父类中定义，子类不需要重复定义
        # 但是 scapy 的字段继承机制不会自动包含父类字段
        # 所以我们需要包含它以便在 show() 时显示
        # 在 do_dissect 中会跳过它，因为父类已经解析过了
        ByteEnumField("Beacon_Type", 0, {0: "Unprovisioned Device Beacon", 1: "Secure Network Beacon", 2: "Mesh Private Beacon"}),
        UUIDField("Device_UUID", None),
        ShortField("OOB_Information", 0),
        IntField("URI_Hash", 0)
    ]
    
    def do_dissect(self, s):
        """重写 do_dissect 以跳过 Beacon_Type 字段（已经在父类中解析）"""
        # Beacon_Type 字段已经在父类中解析，所以跳过第一个字段
        # 直接解析子类的字段（Device_UUID, OOB_Information, URI_Hash）
        for f in self.fields_desc:
            if f.name == "Beacon_Type":
                # 跳过 Beacon_Type 字段，使用父类已经解析的值
                if 'Beacon_Type' not in self.fields:
                    # 如果字段还没有设置，从 underlayer 获取（父类）
                    if self.underlayer and hasattr(self.underlayer, 'fields'):
                        if 'Beacon_Type' in self.underlayer.fields:
                            self.fields['Beacon_Type'] = self.underlayer.fields['Beacon_Type']
                        else:
                            # 如果 underlayer 也没有，使用默认值 0
                            self.fields['Beacon_Type'] = 0
                    else:
                        # 如果没有 underlayer，使用默认值 0
                        self.fields['Beacon_Type'] = 0
                continue
            if not s:
                break
            s, fval = f.getfield(self, s)
            if isinstance(f, ConditionalField) and fval is None:
                continue
            self.fields[f.name] = fval
        return s

    def summary(self, intern=0):
        """返回未配网设备 Beacon 的摘要信息"""
        # 返回简单的类名，与第一个 summary 保持一致
        s = "BLEMesh_Unprovisioned_Device_Beacon"
        if not intern and self.payload and self.payload.__class__.__name__ not in ["NoPayload", "Padding", "Raw", "None"]:
            try:
                s += " / " + self.payload.summary(intern=1)
            except:
                pass
        return s

    def show(self, dump=False, indent=3, lvl="", label_lvl=""):
        """显示未配网设备 Beacon 的详细信息，使用 scapy 标准格式"""
        # 调用父类的 show 方法以使用标准格式
        return super().show(dump=dump, indent=indent, lvl=lvl, label_lvl=label_lvl)


class BLEMesh_Secure_Network_Beacon(BLEMesh_Beacon):
    name = "BLEMesh Secure Network Beacon"

    fields_desc = [
        ByteEnumField("Beacon_Type", 1, {0: "Unprovisioned Device Beacon", 1: "Secure Network Beacon", 2: "Mesh Private Beacon"}),
        BitEnumField("Flag", 0, 8, {0: "Normal operation & Key Refresh False", 1: "Normal operation & Key Refresh True",
                                    2: "IV Update active and Key Refresh False",
                                    3: "IV Update active and Key Refresh True"}),
        LongField("Network_ID", 0),
        IntField("IV_Index", 0),
        LongField("Auth_Value", 0)
    ]
    
    def do_dissect(self, s):
        """重写 do_dissect 以跳过 Beacon_Type 字段（已经在父类中解析）"""
        # Beacon_Type 字段已经在父类中解析，所以跳过第一个字段
        for f in self.fields_desc:
            if f.name == "Beacon_Type":
                # 跳过 Beacon_Type 字段，使用父类已经解析的值
                if 'Beacon_Type' not in self.fields:
                    # 如果字段还没有设置，从 underlayer 获取（父类）
                    if self.underlayer and hasattr(self.underlayer, 'fields'):
                        if 'Beacon_Type' in self.underlayer.fields:
                            self.fields['Beacon_Type'] = self.underlayer.fields['Beacon_Type']
                        else:
                            # 如果 underlayer 也没有，使用默认值 1
                            self.fields['Beacon_Type'] = 1
                    else:
                        # 如果没有 underlayer，使用默认值 1
                        self.fields['Beacon_Type'] = 1
                continue
            if not s:
                break
            s, fval = f.getfield(self, s)
            if isinstance(f, ConditionalField) and fval is None:
                continue
            self.fields[f.name] = fval
        return s

    def summary(self, intern=0):
        """返回安全网络 Beacon 的摘要信息"""
        # 返回简单的类名，与第一个 summary 保持一致
        s = "BLEMesh_Secure_Network_Beacon"
        if not intern and self.payload and self.payload.__class__.__name__ not in ["NoPayload", "Padding", "Raw", "None"]:
            try:
                s += " / " + self.payload.summary(intern=1)
            except:
                pass
        return s

    def show(self, dump=False, indent=3, lvl="", label_lvl=""):
        """显示安全网络 Beacon 的详细信息，使用 scapy 标准格式"""
        # 调用父类的 show 方法以使用标准格式
        return super().show(dump=dump, indent=indent, lvl=lvl, label_lvl=label_lvl)


class BLEMesh_Mesh_Private_Beacon(BLEMesh_Beacon):
    name = "BLEMesh Mesh Private Beacon"
    fields_desc = [
        ByteEnumField("Beacon_Type", 2, {0: "Unprovisioned Device Beacon", 1: "Secure Network Beacon", 2: "Mesh Private Beacon"}),
        StrFixedLenField("random", b"\x00" * 13, 13),
        StrFixedLenField("obf_priv_beacon_data", b"\x00" * 5, 5),
        StrFixedLenField("auth_tag", b"\x00" * 8, 8)
    ]
    
    def do_dissect(self, s):
        """重写 do_dissect 以跳过 Beacon_Type 字段（已经在父类中解析）"""
        # Beacon_Type 字段已经在父类中解析，所以跳过第一个字段
        for f in self.fields_desc:
            if f.name == "Beacon_Type":
                # 跳过 Beacon_Type 字段，使用父类已经解析的值
                if 'Beacon_Type' not in self.fields:
                    # 如果字段还没有设置，从 underlayer 获取（父类）
                    if self.underlayer and hasattr(self.underlayer, 'fields'):
                        if 'Beacon_Type' in self.underlayer.fields:
                            self.fields['Beacon_Type'] = self.underlayer.fields['Beacon_Type']
                        else:
                            # 如果 underlayer 也没有，使用默认值 1
                            self.fields['Beacon_Type'] = 1
                    else:
                        # 如果没有 underlayer，使用默认值 1
                        self.fields['Beacon_Type'] = 1
                continue
            if not s:
                break
            s, fval = f.getfield(self, s)
            if isinstance(f, ConditionalField) and fval is None:
                continue
            self.fields[f.name] = fval
        return s

    def summary(self, intern=0):
        """返回私有 Mesh Beacon 的摘要信息"""
        # 返回简单的类名，与第一个 summary 保持一致
        s = "BLEMesh_Mesh_Private_Beacon"
        if not intern and self.payload and self.payload.__class__.__name__ not in ["NoPayload", "Padding", "Raw", "None"]:
            try:
                s += " / " + self.payload.summary(intern=1)
            except:
                pass
        return s

    def show(self, dump=False, indent=3, lvl="", label_lvl=""):
        """显示私有 Mesh Beacon 的详细信息，使用 scapy 标准格式"""
        # 调用父类的 show 方法以使用标准格式
        return super().show(dump=dump, indent=indent, lvl=lvl, label_lvl=label_lvl)


class PrivateBeaconData(Packet):
    name = "PrivateBeaconData"
    fields_desc = [
        ByteField("flags", 0x00),
        IntField("iv_index", 0x00000000)
    ]


##################### Packet detail #####################
class Provisioning_Data_Unencrypted(Packet):
    name = "Provisioning_Data_Decode"
    fields_desc = [
        StrFixedLenField("NetworkKey", b'\x00' * 16, 16),
        ShortField("KeyIndex", 0),
        ByteField("Flags", 0),
        IntField("IVIndex", 0),
        ShortField("UnicastAddress", 0)

    ]


class Provisioning_Invite(Packet):
    name = "Provisioning_Invite"
    fields_desc = [
        ByteField("ATTENTION_DURATION", 0)
    ]


class Provisioning_Capabilities(Packet):
    name = "Provisioning_Capabilities"

    fields_desc = [
        ByteField("Num_of_Elements", 1),
        ShortField("Algorithms", 1),
        ByteField("PublicKeyType", 0),
        ByteField("StaticOOBType", 0),
        ByteField("OutputOOBSize", 0),
        ShortField("OutputOOBAction", 0),
        ByteField("InputOOBSize", 0),
        ShortField("InputOOBAction", 0)
    ]


class Provisioning_Start(Packet):
    name = "Provisioning_Start"

    fields_desc = [
        ByteField("Algorithm", 0),
        ByteField("PublicKey", 0),
        ByteField("AuthMethod", 0),
        ByteField("AuthAction", 0),
        ByteField("AuthSize", 0),
    ]


class Provisioning_Public_Key(Packet):
    name = "Provisioning_Public_Key"

    fields_desc = [
        StrFixedLenField("PublicKeyX", b'\x00' * 32, 32),
        StrFixedLenField("PublicKeyY", b'\x00' * 32, 32),
    ]


class Provisioning_Input_Complete(Packet):
    name = "Provisioning_Input_Complete"


class Provisioning_Confirmation(Packet):
    """
    Provisioning Confirmation
    Note: Confirmation length depends on algorithm:
    - Algorithm 0 (CMAC-AES128): 16 bytes
    - Algorithm 1 (HMAC-SHA256): 32 bytes
    """
    name = "Provisioning_Confirmation"

    fields_desc = [
        StrFixedLenField("Confirmation", b'\x00' * 16, 16),
    ]
    
    def self_build(self):
        # 在构建数据包之前，根据 Confirmation 的实际长度动态调整字段定义
        if hasattr(self, 'Confirmation') and isinstance(self.Confirmation, bytes):
            if len(self.Confirmation) == 32:
                self.fields_desc = [StrFixedLenField("Confirmation", b'\x00' * 32, 32)]
            elif len(self.Confirmation) == 16:
                self.fields_desc = [StrFixedLenField("Confirmation", b'\x00' * 16, 16)]
        return super().self_build()
    
    def do_dissect(self, s):
        # 动态检测 Confirmation 长度（16 或 32 字节）
        if len(s) >= 32:
            self.fields_desc = [StrFixedLenField("Confirmation", b'\x00' * 32, 32)]
        else:
            self.fields_desc = [StrFixedLenField("Confirmation", b'\x00' * 16, 16)]
        return super().do_dissect(s)


class Provisioning_Random(Packet):
    """
    Provisioning Random
    Note: Random length depends on algorithm:
    - Algorithm 0 (CMAC-AES128): 16 bytes
    - Algorithm 1 (HMAC-SHA256): 32 bytes
    """
    name = "Provisioning_Random"
    fields_desc = [
        StrFixedLenField("Random", b'\x00' * 16, 16),
    ]
    
    def self_build(self):
        # 在构建数据包之前，根据 Random 的实际长度动态调整字段定义
        if hasattr(self, 'Random') and isinstance(self.Random, bytes):
            if len(self.Random) == 32:
                self.fields_desc = [StrFixedLenField("Random", b'\x00' * 32, 32)]
            elif len(self.Random) == 16:
                self.fields_desc = [StrFixedLenField("Random", b'\x00' * 16, 16)]
        return super().self_build()
    
    def do_dissect(self, s):
        # 动态检测 Random 长度（16 或 32 字节）
        if len(s) >= 32:
            self.fields_desc = [StrFixedLenField("Random", b'\x00' * 32, 32)]
        else:
            self.fields_desc = [StrFixedLenField("Random", b'\x00' * 16, 16)]
        return super().do_dissect(s)


class Provisioning_Data(Packet):
    name = "Provisioning_Data"
    fields_desc = [
        StrFixedLenField("EncryptedData", b'\x00' * 25, 25),
        StrFixedLenField("MIC", b'\x00' * 8, 8),
    ]


class Provisioning_Complete(Packet):
    name = "Provisioning_Complete"


class Provisioning_Failed(Packet):
    name = "Provisioning_Failed"
    fields_desc = [
        ByteField("ErrorCode", 0x00),
    ]


#####################
#  BLEMesh Network  #
#####################
# bind_layers(ATT_Write_Command,BLEMesh_Provisioning_Proxy,gatt_handle = 0x0030)
# bind_layers(ATT_Handle_Value_Notification,BLEMesh_Provisioning_Proxy,gatt_handle = 0x0032)
# bind_layers(ATT_Write_Command,BLEMesh_Data_Proxy,gatt_handle = 0x002a)
# bind_layers(ATT_Handle_Value_Notification,BLEMesh_Data_Proxy,gatt_handle = 0x002c)

# bind_layers(BLEMesh_PBADV, GP_PDU)
bind_layers(Message_Decode, Unseg_Access_Message, CTL=0)
bind_layers(Message_Decode, Unseg_Control_Message, CTL=1)
bind_layers(Control_Message, Unseg_Control_Message, SEG=0)
bind_layers(Control_Message, Seg_Control_Message, SEG=1)
bind_layers(Unseg_Control_Message, SegmentAckPayload, Opcode=0x00)

bind_layers(BLEMesh_Provisioning_Proxy, BLEMesh_Provisioning_PDU, SAR=0, Proxy_Type=3)

bind_layers(BLEMesh_Provisioning_Bearer_Control, Link_Open_Message, BearerOpcode=0)
bind_layers(BLEMesh_Provisioning_Bearer_Control, Link_ACK_Message, BearerOpcode=1)
bind_layers(BLEMesh_Provisioning_Bearer_Control, Link_Close_Message, BearerOpcode=2)

bind_layers(BLEMesh_Provisioning_PDU, Provisioning_Invite, PDU_Type=0)
bind_layers(BLEMesh_Provisioning_PDU, Provisioning_Capabilities, PDU_Type=1)
bind_layers(BLEMesh_Provisioning_PDU, Provisioning_Start, PDU_Type=2)
bind_layers(BLEMesh_Provisioning_PDU, Provisioning_Public_Key, PDU_Type=3)
bind_layers(BLEMesh_Provisioning_PDU, Provisioning_Input_Complete, PDU_Type=4)
bind_layers(BLEMesh_Provisioning_PDU, Provisioning_Confirmation, PDU_Type=5)
bind_layers(BLEMesh_Provisioning_PDU, Provisioning_Random, PDU_Type=6)
bind_layers(BLEMesh_Provisioning_PDU, Provisioning_Data, PDU_Type=7)
bind_layers(BLEMesh_Provisioning_PDU, Provisioning_Complete, PDU_Type=8)
bind_layers(BLEMesh_Data_Proxy, BLEMesh_Message, Proxy_Type=0)
bind_layers(BLEMesh_Beacon, BLEMesh_Unprovisioned_Device_Beacon, Beacon_Type=0)
bind_layers(BLEMesh_Beacon, BLEMesh_Secure_Network_Beacon, Beacon_Type=1)
bind_layers(BLEMesh_Beacon, BLEMesh_Mesh_Private_Beacon, Beacon_Type=2)

# 绑定 EIR Header 到 BLE Mesh 层
# 重写 EIR_Hdr 的 guess_payload_class 方法以确保正确解析 BLE Mesh 层
try:
    from scapy.layers.bluetooth import EIR_Hdr, EIR_Raw
    
    # 保存原始的 guess_payload_class 方法
    _original_eir_guess_payload = EIR_Hdr.guess_payload_class
    
    def _eir_guess_payload_class(self, payload):
        """重写 EIR_Hdr 的 guess_payload_class 以支持 BLE Mesh 层"""
        # 首先检查 type 字段
        eir_type = self.getfieldval('type')
        
        # 根据 type 返回对应的 BLE Mesh 层
        if eir_type == 0x29:  # mesh_pb_adv
            return BLEMesh_PBADV
        elif eir_type == 0x2a:  # mesh_message
            return BLEMesh_Message
        elif eir_type == 0x2b:  # mesh_beacon
            return BLEMesh_Beacon
        
        # 对于其他类型，使用原始的猜测方法
        return _original_eir_guess_payload(self, payload)
    
    # 替换 guess_payload_class 方法
    EIR_Hdr.guess_payload_class = _eir_guess_payload_class
    
    # 修复 EIR_Hdr 的 summary 方法，确保包含 payload
    def _eir_summary(self, intern=0):
        """EIR_Hdr 的 summary 方法，确保包含 BLE Mesh 层"""
        # 使用 mysummary 获取基本摘要，如果为空则使用类名
        try:
            s = self.mysummary()
        except:
            s = ""
        if not s:
            s = self.name if hasattr(self, 'name') and self.name else self.__class__.__name__
        
        # 添加 payload 的摘要
        if self.payload and self.payload.__class__.__name__ not in ["NoPayload", "Padding", "Raw", "None"]:
            try:
                payload_summary = self.payload.summary(intern=1)
                if payload_summary:
                    s += " / " + payload_summary
            except Exception as e:
                # 如果 payload.summary() 失败，至少显示类名
                s += " / " + self.payload.__class__.__name__
        
        return s
    
    EIR_Hdr.summary = _eir_summary
    
    # 同时也使用 bind_layers 确保双向绑定（用于构建数据包）
    bind_layers(EIR_Hdr, BLEMesh_PBADV, type=0x29)
    bind_layers(EIR_Hdr, BLEMesh_Message, type=0x2a)
    bind_layers(EIR_Hdr, BLEMesh_Beacon, type=0x2b)
except Exception as e:
    import sys
    print(f"Warning: Failed to patch EIR_Hdr: {e}", file=sys.stderr)

# 也修复 BTLE、BTLE_ADV 和 BTLE_ADV_NONCONN_IND 层的 summary 方法
try:
    from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV, BTLE_ADV_NONCONN_IND
    
    def _btle_mysummary(self):
        """BTLE 的 mysummary 方法 - 使用类名而不是 name 属性"""
        return self.__class__.__name__
    
    BTLE.mysummary = _btle_mysummary
    
    def _btle_adv_mysummary(self):
        """BTLE_ADV 的 mysummary 方法 - 使用类名而不是 name 属性"""
        return self.__class__.__name__
    
    BTLE_ADV.mysummary = _btle_adv_mysummary
    
    def _btle_adv_nonconn_ind_mysummary(self):
        """BTLE_ADV_NONCONN_IND 的 mysummary 方法 - 使用 name 属性"""
        return self.name if hasattr(self, 'name') and self.name else self.__class__.__name__
    
    BTLE_ADV_NONCONN_IND.mysummary = _btle_adv_nonconn_ind_mysummary
    
    def _btle_adv_nonconn_ind_do_summary(self):
        """BTLE_ADV_NONCONN_IND 的 _do_summary 方法，确保包含 data 字段中的 EIR 层"""
        # 首先获取 payload 的 summary
        found, s, needed = 0, "", []
        if self.payload and self.payload.__class__.__name__ not in ["NoPayload"]:
            found, s, needed = self.payload._do_summary()
        
        # 获取当前层的 mysummary
        ret = ""
        if not found or self.__class__ in needed:
            ret = self.mysummary() if hasattr(self, 'mysummary') else ""
            if isinstance(ret, tuple):
                ret, n = ret
                needed += n
        if ret or needed:
            found = 1
        if not ret:
            ret = self.name if hasattr(self, 'name') and self.name else self.__class__.__name__
        
        # 添加 data 字段中的 EIR 层
        if hasattr(self, 'data') and self.data:
            for eir_pkt in self.data:
                if eir_pkt and eir_pkt.__class__.__name__ not in ["NoPayload", "Padding", "None"]:
                    try:
                        _, eir_summary, _ = eir_pkt._do_summary()
                        if eir_summary:
                            ret = "%s / %s" % (ret, eir_summary)
                    except Exception as e:
                        # 如果失败，至少显示类名
                        ret = "%s / %s" % (ret, eir_pkt.__class__.__name__)
        
        # 连接 payload 的 summary
        if ret and s:
            ret = "%s / %s" % (ret, s)
        else:
            ret = "%s%s" % (ret, s)
        
        return found, ret, needed
    
    BTLE_ADV_NONCONN_IND._do_summary = _btle_adv_nonconn_ind_do_summary
except Exception as e:
    import sys
    print(f"Warning: Failed to patch BTLE_ADV/BTLE_ADV_NONCONN_IND: {e}", file=sys.stderr)


###################
# defragmentation #
###################
# The PB-ADV bearer MTU (Maximum Transmission Unit) ssize is 24 octets.
def PB_ADV_defragment(plist):
    """defragment PB-ADV datagrams"""
    len = 0
    crc = 0
    PDU = bytes()
    packet = BLEMesh_Provisioning_PDU()
    for p in plist:
        PDU = PDU + bytes(p.payload.payload)
    packet.PDU_Padding = PDU[0] >> 6 & 0b11
    packet.PDU_Type = PDU[0] & 0b111111
    packet.payload = Raw(PDU[1:])
    return packet


# The PB-GATT bearer MTU (Maximum Transmission Unit) ssize is 20 octets.
def packet_fragment(pkt, fragsize=19) -> List[Packet]:
    p = pkt
    lst = []
    total_len = len(raw(p))
    nb = total_len // fragsize + 1
    for i in range(nb):
        if i == 0:
            f = raw(p)[0:(fragsize)]
        elif i == nb - 1:
            f = raw(p)[fragsize + (i - 1) * (fragsize):]
        else:
            f = raw(p)[(i) * (fragsize):(i + 1) * (fragsize)]
        lst.append(f)
    return lst


def Provisioning_defragment(plist) -> Packet:
    PDU = bytes()
    BLEMesh_Provisioning_PDU
    for p in plist:
        PDU = PDU + bytes(p.payload)
    packet = BLEMesh_Provisioning_PDU(PDU)
    return packet


# def Access_Message_defragment(plist):


###################
#  Message Decode #
###################
# Process Mesh Message Obfuscated and Encrypted_data_NetMIC
def packet_decrypt(pkt):
    en_packet = raw(pkt)
    de_packet = decrypt(en_packet)


###################
#  Model Layer Parser #
###################
def parse_bluetooth_mesh_model_message(data):
    """
    解析蓝牙Mesh模型层消息
    
    Args:
        data: 模型层数据（字节数据）
    
    Returns:
        Packet对象，如果无法解析则返回None
    """
    if not data or len(data) < 1:
        return None
    
    try:
        # 解析Opcode
        opcode = None
        opcode_len = 0
        
        if data[0] & 0x80 == 0:  # 1字节Opcode (0xxxxxxx)
            opcode = data[0]
            opcode_len = 1
        elif data[0] & 0xC0 == 0x80:  # 2字节Opcode (10xxxxxx)
            if len(data) >= 2:
                opcode = int.from_bytes(data[0:2], 'big')
                opcode_len = 2
            else:
                return None
        elif data[0] & 0xC0 == 0xC0:  # 3字节Opcode (11xxxxxx)
            if len(data) >= 3:
                opcode = int.from_bytes(data[0:3], 'big')
                opcode_len = 3
            else:
                return None
        else:
            return None
        
        # 获取参数数据（去掉Opcode）
        params = data[opcode_len:] if len(data) > opcode_len else b""
        
        # 根据Opcode创建相应的Packet对象
        if opcode == 0x02:  # Config Composition Data Status
            if len(params) >= 1:
                page = params[0]
                composition_data = params[1:] if len(params) > 1 else b""
                return ConfigCompositionDataStatus(opcode=opcode, page=page, data=composition_data)
            else:
                return ConfigCompositionDataStatus(opcode=opcode, page=0, data=b"")
        
        elif opcode == 0x8008:  # Config Composition Data Get
            page = params[0] if len(params) >= 1 else 0
            return ConfigCompositionDataGet(opcode=opcode, page=page)
        
        elif opcode == 0x8009:  # Config Beacon Get
            return ConfigBeaconGet(opcode=opcode)
        
        elif opcode == 0x800A:  # Config Beacon Set
            beacon = params[0] if len(params) >= 1 else 0
            return ConfigBeaconSet(opcode=opcode, beacon=beacon)
        
        elif opcode == 0x800B:  # Config Beacon Status
            beacon = params[0] if len(params) >= 1 else 0
            return ConfigBeaconStatus(opcode=opcode, beacon=beacon)
        
        elif opcode == 0x800C:  # Config Default TTL Get
            return ConfigDefaultTTLGet(opcode=opcode)
        
        elif opcode == 0x800D:  # Config Default TTL Set
            ttl = params[0] if len(params) >= 1 else 0
            return ConfigDefaultTTLSet(opcode=opcode, ttl=ttl)
        
        elif opcode == 0x800E:  # Config Default TTL Status
            ttl = params[0] if len(params) >= 1 else 0
            return ConfigDefaultTTLStatus(opcode=opcode, ttl=ttl)

        # ---------- Config Friend ----------
        elif opcode == 0x800F:  # Config Friend Get
            return ConfigFriendGet(opcode=opcode)

        elif opcode == 0x8010:  # Config Friend Set
            friend = params[0] if len(params) >= 1 else 0
            return ConfigFriendSet(opcode=opcode, friend=friend)

        elif opcode == 0x8011:  # Config Friend Status
            if len(params) >= 2:
                status = params[0]
                friend = params[1]
                return ConfigFriendStatus(opcode=opcode, status=status, friend=friend)
            else:
                return ConfigFriendStatus(opcode=opcode, status=0, friend=0)

        # ---------- Config GATT Proxy ----------
        elif opcode == 0x8012:  # Config GATT Proxy Get
            return ConfigGATTProxyGet(opcode=opcode)
        
        elif opcode == 0x8013:  # Config GATT Proxy Set
            gatt_proxy = params[0] if len(params) >= 1 else 0
            return ConfigGATTProxySet(opcode=opcode, gatt_proxy=gatt_proxy)
        
        elif opcode == 0x8014:  # Config GATT Proxy Status
            gatt_proxy = params[0] if len(params) >= 1 else 0
            return ConfigGATTProxyStatus(opcode=opcode, gatt_proxy=gatt_proxy)

        # ---------- Config Key Refresh Phase ----------
        elif opcode == 0x8015:  # Config Key Refresh Phase Get
            return ConfigKeyRefreshPhaseGet(opcode=opcode)
        
        elif opcode == 0x8016:  # Config Key Refresh Phase Set
            if len(params) >= 2:
                net_key_index = params[0]
                transition = params[1]
                return ConfigKeyRefreshPhaseSet(opcode=opcode, net_key_index=net_key_index, transition=transition)
            else:
                return None
        
        elif opcode == 0x8017:  # Config Key Refresh Phase Status
            if len(params) >= 4:
                status = params[0]
                net_key_index = int.from_bytes(params[1:3], 'little')  # 2 bytes, little endian
                phase = params[3]
                return ConfigKeyRefreshPhaseStatus(opcode=opcode, status=status, net_key_index=net_key_index, phase=phase)
            else:
                return ConfigKeyRefreshPhaseStatus(opcode=opcode, status=0, net_key_index=0, phase=0)

        # ---------- Config Heartbeat Publication ----------
        elif opcode == 0x8038:  # Config Heartbeat Publication Get
            return ConfigHeartbeatPublicationGet(opcode=opcode)
        
        elif opcode == 0x8039:  # Config Heartbeat Publication Set
            if len(params) >= 9:
                destination = int.from_bytes(params[0:2], 'little')
                count_log = params[2]
                period_log = params[3]
                ttl = params[4]
                features = int.from_bytes(params[5:7], 'little')
                net_key_index = int.from_bytes(params[7:9], 'little')
                return ConfigHeartbeatPublicationSet(opcode=opcode, destination=destination, count_log=count_log,
                                                    period_log=period_log, ttl=ttl, features=features, net_key_index=net_key_index)
            else:
                return None
        
        elif opcode == 0x06:  # Config Heartbeat Publication Status (1-byte opcode)
            if len(params) >= 9:
                status = params[0]
                destination = int.from_bytes(params[1:3], 'little')
                count_log = params[3]
                period_log = params[4]
                ttl = params[5]
                features = int.from_bytes(params[6:8], 'little')
                net_key_index = int.from_bytes(params[8:10], 'little')
                return ConfigHeartbeatPublicationStatus(opcode=opcode, status=status, destination=destination,
                                                       count_log=count_log, period_log=period_log, ttl=ttl,
                                                       features=features, net_key_index=net_key_index)
            else:
                return ConfigHeartbeatPublicationStatus(opcode=opcode, status=0, destination=0, count_log=0,
                                                       period_log=0, ttl=0, features=0, net_key_index=0)

        # ---------- Config Heartbeat Subscription ----------
        elif opcode == 0x803A:  # Config Heartbeat Subscription Get
            return ConfigHeartbeatSubscriptionGet(opcode=opcode)
        
        elif opcode == 0x803B:  # Config Heartbeat Subscription Set
            if len(params) >= 5:
                source = int.from_bytes(params[0:2], 'little')
                destination = int.from_bytes(params[2:4], 'little')
                period_log = params[4]
                return ConfigHeartbeatSubscriptionSet(opcode=opcode, source=source, destination=destination, period_log=period_log)
            else:
                return None
        
        elif opcode == 0x803C:  # Config Heartbeat Subscription Status
            if len(params) >= 8:
                status = params[0]
                source = int.from_bytes(params[1:3], 'little')
                destination = int.from_bytes(params[3:5], 'little')
                period_log = params[5]
                count_log = params[6]
                min_hops = params[7]
                max_hops = params[8] if len(params) >= 9 else 0
                return ConfigHeartbeatSubscriptionStatus(opcode=opcode, status=status, source=source,
                                                       destination=destination, period_log=period_log,
                                                       count_log=count_log, min_hops=min_hops, max_hops=max_hops)
            else:
                return ConfigHeartbeatSubscriptionStatus(opcode=opcode, status=0, source=0, destination=0,
                                                       period_log=0, count_log=0, min_hops=0, max_hops=0)

        # ---------- Config Low Power Node PollTimeout ----------
        elif opcode == 0x802D:  # Config Low Power Node PollTimeout Get
            if len(params) >= 2:
                lpn_address = int.from_bytes(params[0:2], 'little')
                return ConfigLowPowerNodePollTimeoutGet(opcode=opcode, lpn_address=lpn_address)
            else:
                return ConfigLowPowerNodePollTimeoutGet(opcode=opcode, lpn_address=0)

        # ---------- Config Relay ----------
        elif opcode == 0x8026:  # Config Relay Get
            return ConfigRelayGet(opcode=opcode)
        
        elif opcode == 0x8027:  # Config Relay Set
            if len(params) >= 3:
                relay = params[0]
                relay_retransmit_count = params[1]
                relay_retransmit_interval_steps = params[2]
                return ConfigRelaySet(opcode=opcode, relay=relay, relay_retransmit_count=relay_retransmit_count,
                                     relay_retransmit_interval_steps=relay_retransmit_interval_steps)
            else:
                return None
        
        elif opcode == 0x8028:  # Config Relay Status
            if len(params) >= 3:
                relay = params[0]
                relay_retransmit_count = params[1]
                relay_retransmit_interval_steps = params[2]
                return ConfigRelayStatus(opcode=opcode, relay=relay, relay_retransmit_count=relay_retransmit_count,
                                       relay_retransmit_interval_steps=relay_retransmit_interval_steps)
            else:
                return ConfigRelayStatus(opcode=opcode, relay=0, relay_retransmit_count=0,
                                       relay_retransmit_interval_steps=0)

        # ---------- Config SIG Model Subscription ----------
        elif opcode == 0x8029:  # Config SIG Model Subscription Get
            if len(params) >= 4:
                element_address = int.from_bytes(params[0:2], 'little')
                model_id = int.from_bytes(params[2:4], 'little')
                return ConfigSIGModelSubscriptionGet(opcode=opcode, element_address=element_address, model_id=model_id)
            else:
                return ConfigSIGModelSubscriptionGet(opcode=opcode, element_address=0, model_id=0)

        # ---------- Config Node Identity ----------
        elif opcode == 0x8046:  # Config Node Identity Get
            if len(params) >= 2:
                net_key_index = int.from_bytes(params[0:2], 'little')
                return ConfigNodeIdentityGet(opcode=opcode, net_key_index=net_key_index)
            else:
                return ConfigNodeIdentityGet(opcode=opcode, net_key_index=0)
        
        elif opcode == 0x8047:  # Config Node Identity Set
            if len(params) >= 3:
                net_key_index = int.from_bytes(params[0:2], 'little')
                identity = params[2]
                return ConfigNodeIdentitySet(opcode=opcode, net_key_index=net_key_index, identity=identity)
            else:
                return None
        
        elif opcode == 0x8048:  # Config Node Identity Status
            if len(params) >= 4:
                status = params[0]
                net_key_index = int.from_bytes(params[1:3], 'little')
                identity = params[3]
                return ConfigNodeIdentityStatus(opcode=opcode, status=status, net_key_index=net_key_index, identity=identity)
            else:
                return ConfigNodeIdentityStatus(opcode=opcode, status=0, net_key_index=0, identity=0)

        # ---------- Config Node Reset ----------
        elif opcode == 0x8049:  # Config Node Reset
            return ConfigNodeReset(opcode=opcode)
        
        elif opcode == 0x804A:  # Config Node Reset Status
            return ConfigNodeResetStatus(opcode=opcode)

        # ---------- Config Model App Bind/Unbind/Status ----------
        elif opcode == 0x803D:  # Config Model App Bind
            if len(params) >= 4:
                element_address = int.from_bytes(params[0:2], 'little')
                app_key_index = int.from_bytes(params[2:4], 'little')
                model_identifier = params[4:] if len(params) > 4 else b""
                return ConfigModelAppBind(opcode=opcode, element_address=element_address,
                                         app_key_index=app_key_index, model_identifier=model_identifier)
            else:
                return ConfigModelAppBind(opcode=opcode, element_address=0, app_key_index=0, model_identifier=b"")
        
        elif opcode == 0x803E:  # Config Model App Status
            if len(params) >= 5:
                status = params[0]
                element_address = int.from_bytes(params[1:3], 'little')
                app_key_index = int.from_bytes(params[3:5], 'little')
                model_identifier = params[5:] if len(params) > 5 else b""
                return ConfigModelAppStatus(opcode=opcode, status=status, element_address=element_address,
                                           app_key_index=app_key_index, model_identifier=model_identifier)
            else:
                return ConfigModelAppStatus(opcode=opcode, status=0, element_address=0, app_key_index=0, model_identifier=b"")
        
        elif opcode == 0x803F:  # Config Model App Unbind
            if len(params) >= 4:
                element_address = int.from_bytes(params[0:2], 'little')
                app_key_index = int.from_bytes(params[2:4], 'little')
                model_identifier = params[4:] if len(params) > 4 else b""
                return ConfigModelAppUnbind(opcode=opcode, element_address=element_address,
                                           app_key_index=app_key_index, model_identifier=model_identifier)
            else:
                return ConfigModelAppUnbind(opcode=opcode, element_address=0, app_key_index=0, model_identifier=b"")

        # ---------- Config SIG Model App ----------
        elif opcode == 0x804B:  # Config SIG Model App Get
            if len(params) >= 4:
                element_address = int.from_bytes(params[0:2], 'little')
                model_id = int.from_bytes(params[2:4], 'little')
                return ConfigSIGModelAppGet(opcode=opcode, element_address=element_address, model_id=model_id)
            else:
                return ConfigSIGModelAppGet(opcode=opcode, element_address=0, model_id=0)
        
        elif opcode == 0x804C:  # Config SIG Model App List
            if len(params) >= 5:
                status = params[0]
                element_address = int.from_bytes(params[1:3], 'little')
                model_id = int.from_bytes(params[3:5], 'little')
                app_key_indexes = params[5:] if len(params) > 5 else b""
                return ConfigSIGModelAppList(opcode=opcode, status=status, element_address=element_address,
                                            model_id=model_id, app_key_indexes=app_key_indexes)
            else:
                return ConfigSIGModelAppList(opcode=opcode, status=0, element_address=0, model_id=0, app_key_indexes=b"")

        # ---------- Config NetKey messages ----------
        elif opcode == 0x8040:  # Config NetKey Add
            # NetKeyIndex (2 octets, packed 12-bit, 这里先按 little-endian 解析) + NetKey (16 octets)
            if len(params) >= 18:
                net_key_index = int.from_bytes(params[0:2], "little")
                net_key = params[2:18]
                return ConfigNetworkKeyAdd(opcode=opcode, net_key_index=net_key_index, net_key=net_key)
            else:
                return None

        elif opcode == 0x8041:  # Config NetKey Delete
            if len(params) >= 2:
                net_key_index = int.from_bytes(params[0:2], "little")
                return ConfigNetworkKeyDelete(opcode=opcode, net_key_index=net_key_index)
            else:
                return None

        elif opcode == 0x8042:  # Config NetKey Get
            # 有的实现允许省略 NetKeyIndex（获取所有），所以这里长度不足时给 0
            net_key_index = int.from_bytes(params[0:2], "little") if len(params) >= 2 else 0
            return ConfigNetworkKeyGet(opcode=opcode, net_key_index=net_key_index)

        elif opcode == 0x8045:  # Config NetKey Update
            if len(params) >= 18:
                net_key_index = int.from_bytes(params[0:2], "little")
                net_key = params[2:18]
                return ConfigNetworkKeyUpdate(opcode=opcode, net_key_index=net_key_index, net_key=net_key)
            else:
                return None

        # ---------- Config AppKey messages ----------
        elif opcode == 0x00:  # Config App Key Add
            if len(params) >= 20:
                net_key_index = int.from_bytes(params[0:2], 'little')
                app_key_index = int.from_bytes(params[2:4], 'little')
                app_key = params[4:20]
                return ConfigAppKeyAdd(opcode=opcode, net_key_index=net_key_index, 
                                      app_key_index=app_key_index, app_key=app_key)
            else:
                return None
        
        elif opcode == 0x8000:  # Config App Key Delete
            if len(params) >= 4:
                net_key_index = int.from_bytes(params[0:2], 'little')
                app_key_index = int.from_bytes(params[2:4], 'little')
                return ConfigAppKeyDelete(opcode=opcode, net_key_index=net_key_index, 
                                         app_key_index=app_key_index)
            else:
                return None
        
        elif opcode == 0x8001:  # Config App Key Get
            if len(params) >= 2:
                net_key_index = int.from_bytes(params[0:2], 'little')
                return ConfigAppKeyGet(opcode=opcode, net_key_index=net_key_index)
            else:
                return ConfigAppKeyGet(opcode=opcode, net_key_index=0)
        
        elif opcode == 0x8002:  # Config App Key List
            # 格式：Status(1) + NetKeyIndex(2) + AppKeyIndexList(可选)
            if len(params) >= 3:
                status = params[0]
                net_key_index = int.from_bytes(params[1:3], 'little')
                app_key_indexes = params[3:] if len(params) > 3 else b""
                return ConfigAppKeyList(opcode=opcode, status=status,
                                       net_key_index=net_key_index, app_key_indexes=app_key_indexes)
            else:
                return None
        
        elif opcode == 0x8003:  # Config App Key Status
            if len(params) >= 4:
                status = params[0]
                packed_indexes = int.from_bytes(params[1:4], 'big')
                return ConfigAppKeyStatus(opcode=opcode, status=status, packed_indexes=packed_indexes)
            else:
                return ConfigAppKeyStatus(opcode=opcode, status=0, packed_indexes=0)
        
        elif opcode == 0x01:  # Config App Key Update (1-octet opcode)
            if len(params) >= 19:  # 3 bytes indexes + 16 bytes appkey
                packed_indexes = int.from_bytes(params[0:3], 'little')
                app_key = params[3:19]
                return ConfigAppKeyUpdate(opcode=opcode, packed_indexes=packed_indexes, app_key=app_key)
            else:
                return None

        elif opcode == 0x8043:  # Config Network Key List
            # 按规范：Status(1) + NetKeyIndex(2) + NetKeyList(可变)，这里只是先整体保存索引列表
            net_key_indexes = params
            return ConfigNetworkKeyList(opcode=opcode, net_key_indexes=net_key_indexes)

        elif opcode == 0x8044:  # Config Network Key Status
            if len(params) >= 3:
                status = params[0]
                net_key_index = int.from_bytes(params[1:3], 'big')
                return ConfigNetworkKeyStatus(opcode=opcode, status=status, net_key_index=net_key_index)
            else:
                return ConfigNetworkKeyStatus(opcode=opcode, status=0, net_key_index=0)
        
        elif opcode == 0x8201:  # Generic OnOff Get
            return GenericOnOffGet(opcode=opcode)
        
        elif opcode == 0x8202:  # Generic OnOff Set
            if len(params) >= 2:
                on_off = params[0]
                tid = params[1]
                transition_time = params[2] if len(params) >= 3 else 0
                delay = params[3] if len(params) >= 4 else 0
                return GenericOnOffSet(opcode=opcode, on_off=on_off, tid=tid, 
                                      transition_time=transition_time, delay=delay)
            else:
                return None
        
        elif opcode == 0x8203:  # Generic OnOff Set Unacknowledged
            if len(params) >= 2:
                on_off = params[0]
                tid = params[1]
                transition_time = params[2] if len(params) >= 3 else 0
                delay = params[3] if len(params) >= 4 else 0
                return GenericOnOffSetUnacknowledged(opcode=opcode, on_off=on_off, tid=tid,
                                                     transition_time=transition_time, delay=delay)
            else:
                return None
        
        elif opcode == 0x8204:  # Generic OnOff Status
            if len(params) >= 1:
                present_on_off = params[0]
                target_on_off = params[1] if len(params) >= 2 else 0
                remaining_time = params[2] if len(params) >= 3 else 0
                return GenericOnOffStatus(opcode=opcode, present_on_off=present_on_off,
                                         target_on_off=target_on_off, remaining_time=remaining_time)
            else:
                return None
        
        else:
            # 未知的Opcode，返回通用消息对象
            opcode_bytes = data[0:opcode_len]
            return GenericModelMessage(opcode=opcode_bytes, parameters=params)

    except Exception as e:
        # 解析失败，返回None
        return None


# ==============================================
# BLE Mesh 解析辅助函数
# ==============================================

def parse_ble_mesh_beacon(pkt):
    """
    解析 BLE Mesh Beacon 层信息
    
    参数:
        pkt: Scapy 数据包对象
    
    返回:
        dict: 解析后的 Beacon 信息，如果不是 Beacon 包则返回 None
    """
    if not pkt.haslayer("BLEMesh_Beacon"):
        return None
    
    beacon = pkt["BLEMesh_Beacon"]
    result = {
        "beacon_type": beacon.Beacon_Type,
        "beacon_type_name": {
            0: "Unprovisioned Device Beacon",
            1: "Secure Network Beacon",
            2: "Mesh Private Beacon"
        }.get(beacon.Beacon_Type, "Unknown")
    }
    
    # 解析 Unprovisioned Device Beacon
    if pkt.haslayer("BLEMesh Unprovisioned Device Beacon"):
        unprov = pkt["BLEMesh Unprovisioned Device Beacon"]
        result["device_uuid"] = str(unprov.Device_UUID) if unprov.Device_UUID else None
        result["oob_information"] = unprov.OOB_Information
        result["uri_hash"] = unprov.URI_Hash
    
    # 解析 Secure Network Beacon
    elif pkt.haslayer("BLEMesh Secure Network Beacon"):
        secure = pkt["BLEMesh Secure Network Beacon"]
        result["flag"] = secure.Flag
        result["flag_description"] = {
            0: "Normal operation & Key Refresh False",
            1: "Normal operation & Key Refresh True",
            2: "IV Update active and Key Refresh False",
            3: "IV Update active and Key Refresh True"
        }.get(secure.Flag, "Unknown")
        result["network_id"] = f"0x{secure.Network_ID:016x}"
        result["iv_index"] = secure.IV_Index
        result["auth_value"] = f"0x{secure.Auth_Value:016x}"
    
    # 解析 Mesh Private Beacon
    elif pkt.haslayer("BLEMesh Mesh Private Beacon"):
        private = pkt["BLEMesh Mesh Private Beacon"]
        result["random"] = private.random.hex() if hasattr(private.random, 'hex') else str(private.random)
        result["obf_priv_beacon_data"] = private.obf_priv_beacon_data.hex() if hasattr(private.obf_priv_beacon_data, 'hex') else str(private.obf_priv_beacon_data)
        result["auth_tag"] = private.auth_tag.hex() if hasattr(private.auth_tag, 'hex') else str(private.auth_tag)
    
    return result


def parse_ble_mesh_message(pkt):
    """
    解析 BLE Mesh Message 层信息
    
    参数:
        pkt: Scapy 数据包对象
    
    返回:
        dict: 解析后的 Message 信息，如果不是 Message 包则返回 None
    """
    if not pkt.haslayer("BLEMesh_Message"):
        return None
    
    mesh_msg = pkt["BLEMesh_Message"]
    result = {
        "ivi": mesh_msg.IVI,
        "nid": mesh_msg.NID,
        "obfuscated": mesh_msg.Obfuscated.hex() if hasattr(mesh_msg.Obfuscated, 'hex') else str(mesh_msg.Obfuscated),
        "encrypted_data_netmic": mesh_msg.Encrypted_data_NetMIC.hex() if hasattr(mesh_msg.Encrypted_data_NetMIC, 'hex') else str(mesh_msg.Encrypted_data_NetMIC),
        "encrypted_data_length": len(mesh_msg.Encrypted_data_NetMIC) if mesh_msg.Encrypted_data_NetMIC else 0
    }
    
    return result


def print_ble_mesh_info(pkt, color=True):
    """
    打印 BLE Mesh 层的详细信息（美化输出）
    
    参数:
        pkt: Scapy 数据包对象
        color: 是否使用彩色输出（需要 colorama 库）
    """
    try:
        from colorama import Fore, Style
        if not color:
            Fore.CYAN = Fore.GREEN = Fore.YELLOW = Style.RESET_ALL = ""
    except ImportError:
        Fore = type('Fore', (), {'CYAN': '', 'GREEN': '', 'YELLOW': ''})()
        Style = type('Style', (), {'RESET_ALL': ''})()
    
    # 解析 Beacon 层
    beacon_info = parse_ble_mesh_beacon(pkt)
    if beacon_info:
        print(Fore.CYAN + "=" * 50)
        print("BLE Mesh Beacon 层解析")
        print("=" * 50 + Style.RESET_ALL)
        print(f"{Fore.GREEN}Beacon类型:{Style.RESET_ALL} {beacon_info['beacon_type_name']} ({beacon_info['beacon_type']})")
        
        if "device_uuid" in beacon_info:
            print(f"{Fore.GREEN}设备UUID:{Style.RESET_ALL} {beacon_info['device_uuid']}")
            print(f"{Fore.GREEN}OOB信息:{Style.RESET_ALL} 0x{beacon_info['oob_information']:04x}")
            if beacon_info['uri_hash'] != 0:
                print(f"{Fore.GREEN}URI哈希:{Style.RESET_ALL} 0x{beacon_info['uri_hash']:08x}")
        
        elif "network_id" in beacon_info:
            print(f"{Fore.GREEN}标志:{Style.RESET_ALL} {beacon_info['flag']} - {beacon_info['flag_description']}")
            print(f"{Fore.GREEN}网络ID:{Style.RESET_ALL} {beacon_info['network_id']}")
            print(f"{Fore.GREEN}IV索引:{Style.RESET_ALL} {beacon_info['iv_index']} (0x{beacon_info['iv_index']:08x})")
            print(f"{Fore.GREEN}认证值:{Style.RESET_ALL} {beacon_info['auth_value']}")
        
        elif "random" in beacon_info:
            print(f"{Fore.GREEN}随机数:{Style.RESET_ALL} {beacon_info['random']}")
            print(f"{Fore.GREEN}混淆私有Beacon数据:{Style.RESET_ALL} {beacon_info['obf_priv_beacon_data']}")
            print(f"{Fore.GREEN}认证标签:{Style.RESET_ALL} {beacon_info['auth_tag']}")
        
        print()
    
    # 解析 Message 层
    message_info = parse_ble_mesh_message(pkt)
    if message_info:
        print(Fore.CYAN + "=" * 50)
        print("BLE Mesh Message 层解析")
        print("=" * 50 + Style.RESET_ALL)
        print(f"{Fore.GREEN}IVI:{Style.RESET_ALL} {message_info['ivi']}")
        print(f"{Fore.GREEN}NID:{Style.RESET_ALL} {message_info['nid']}")
        print(f"{Fore.GREEN}混淆数据:{Style.RESET_ALL} {message_info['obfuscated'][:32]}{'...' if len(message_info['obfuscated']) > 32 else ''}")
        print(f"{Fore.GREEN}加密数据长度:{Style.RESET_ALL} {message_info['encrypted_data_length']} 字节")
        if message_info['encrypted_data_length'] > 0:
            encrypted_preview = message_info['encrypted_data_netmic'][:32]
            print(f"{Fore.GREEN}加密数据预览:{Style.RESET_ALL} {encrypted_preview}{'...' if len(message_info['encrypted_data_netmic']) > 32 else ''}")
        print()


def has_ble_mesh_layer(pkt):
    """
    检查数据包是否包含 BLE Mesh 层
    
    参数:
        pkt: Scapy 数据包对象
    
    返回:
        bool: 如果包含任何 BLE Mesh 层则返回 True
    """
    return pkt.haslayer("BLEMesh_Beacon") or pkt.haslayer("BLEMesh_Message")


def get_full_summary(pkt):
    """
    获取数据包的完整摘要，包括所有层（特别是 BLE Mesh 层）
    
    参数:
        pkt: Scapy 数据包对象
    
    返回:
        str: 包含所有层的完整摘要字符串
    
    示例:
        >>> summary = get_full_summary(pkt)
        >>> print(summary)
        BTLE / BTLE_ADV / BTLE_ADV_NONCONN_IND / EIR_Header / BLEMesh_Beacon / BLEMesh Unprovisioned Device Beacon
    """
    summary_parts = []
    current_layer = pkt
    
    while current_layer:
        layer_name = current_layer.__class__.__name__
        
        # 添加层信息
        if layer_name == "Raw":
            # 对于 Raw 层，只显示数据长度（如果有数据）
            if len(current_layer) > 0:
                summary_parts.append(f"Raw(len={len(current_layer)})")
        elif layer_name == "NoPayload":
            # 跳过 NoPayload 层
            break
        elif hasattr(current_layer, 'summary'):
            # 使用层自己的 summary 方法
            try:
                layer_summary = current_layer.summary()
                # 只取第一个部分（不包括子层，因为我们会遍历它们）
                if " / " in layer_summary:
                    layer_summary = layer_summary.split(" / ")[0]
                summary_parts.append(layer_summary)
            except:
                # 如果 summary 方法失败，使用类名
                summary_parts.append(layer_name)
        else:
            # 没有 summary 方法，直接使用类名
            summary_parts.append(layer_name)
        
        # 移动到下一层（payload）
        if hasattr(current_layer, 'payload'):
            current_layer = current_layer.payload
            # 检查是否已经到达末尾
            if current_layer is None or isinstance(current_layer, type(None)):
                break
            if hasattr(current_layer, '__class__') and current_layer.__class__.__name__ == "NoPayload":
                break
        else:
            break
    
    return " / ".join(summary_parts)


def get_ble_mesh_summary(pkt):
    """
    获取 BLE Mesh 层的简短摘要信息
    
    参数:
        pkt: Scapy 数据包对象
    
    返回:
        str: BLE Mesh 层的摘要信息，如果没有 BLE Mesh 层则返回空字符串
    
    示例:
        >>> summary = get_ble_mesh_summary(pkt)
        >>> print(summary)
        "Unprovisioned Device Beacon (UUID: dddd188b...)"
    """
    if not has_ble_mesh_layer(pkt):
        return ""
    
    # 检查 Beacon 层
    if pkt.haslayer("BLEMesh_Beacon"):
        beacon = pkt["BLEMesh_Beacon"]
        beacon_type = beacon.Beacon_Type
        
        if beacon_type == 0 and pkt.haslayer("BLEMesh Unprovisioned Device Beacon"):
            unprov = pkt["BLEMesh Unprovisioned Device Beacon"]
            uuid_str = str(unprov.Device_UUID)[:13] if unprov.Device_UUID else "None"
            return f"Unprovisioned Device Beacon (UUID: {uuid_str}...)"
        
        elif beacon_type == 1 and pkt.haslayer("BLEMesh Secure Network Beacon"):
            secure = pkt["BLEMesh Secure Network Beacon"]
            return f"Secure Network Beacon (NetID: 0x{secure.Network_ID:016x}, IV: {secure.IV_Index})"
        
        elif beacon_type == 2 and pkt.haslayer("BLEMesh Mesh Private Beacon"):
            return f"Mesh Private Beacon"
    
    # 检查 Message 层
    if pkt.haslayer("BLEMesh_Message"):
        mesh_msg = pkt["BLEMesh_Message"]
        return f"BLEMesh Message (IVI: {mesh_msg.IVI}, NID: {mesh_msg.NID})"
    
    return ""


