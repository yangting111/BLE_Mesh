import random
import sys
import os
from types import EllipsisType

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/../../")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/../libs/")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/../libs/boofuzz/")


from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from scapy.packet import Packet, raw, Raw
from scapy.contrib.ble_mesh import *
from Transfer.libs.ble_mesh_decrypter.ble_mesh_decrypter import MeshDecrypter
from scapy.all import hexdump
from Transfer.Send_Packet.packet_handle import Packet_Handle



class Ble_Mesh_Beacon():
    def __init__(self, advertiser_address: str):
        self.name = "ble_mesh_beacon"
        self.advertiser_address = advertiser_address

    def UNPROVISIONED_DEVICE_BEACON(self):
        """创建未配网设备 Beacon"""
        beacon = BLEMesh_Unprovisioned_Device_Beacon()
        pkt = BTLE() / BTLE_ADV() / BTLE_ADV_NONCONN_IND(AdvA=self.advertiser_address) / EIR_Hdr(
            type=0x2b) / beacon
        return pkt

    def SECURE_NETWORK_BEACON(self):
        """创建安全网络 Beacon"""
        beacon = BLEMesh_Secure_Network_Beacon()
        pkt = BTLE() / BTLE_ADV() / BTLE_ADV_NONCONN_IND(AdvA=self.advertiser_address) / EIR_Hdr(
            type=0x2b) / beacon
        return pkt

    def MESH_PRIVATE_BEACON(self):
        """创建私有 Mesh Beacon"""
        beacon = BLEMesh_Mesh_Private_Beacon()
        pkt = BTLE() / BTLE_ADV() / BTLE_ADV_NONCONN_IND(AdvA=self.advertiser_address) / EIR_Hdr(
            type=0x2b) / beacon
        return pkt


class Ble_Mesh_Beacon_Handler():
    def __init__(self, mesh_decrypter: MeshDecrypter = None):
        self.mesh_decrypter = mesh_decrypter
        self.packet_handle = Packet_Handle()
        # self.network_key = None
        # if mesh_decrypter:
        #     self.network_key = mesh_decrypter.
        #     print("network_key: ", self.network_key.key.hex())
        # else:
        #     print("Error: mesh_decrypter is not initialized")

    def receive_beacon_handler(self, pkt: Packet):
        """处理接收到的 Beacon 包"""
        # print(f"receive_beacon_handler: {pkt.summary()}")
        
        if pkt.haslayer("BLEMesh_Unprovisioned_Device_Beacon"):
            beacon = pkt.getlayer("BLEMesh_Unprovisioned_Device_Beacon")
            # print(f"收到未配网设备 Beacon: UUID={beacon.Device_UUID}, OOB={beacon.OOB_Information}")
            return pkt
        
        elif pkt.haslayer("BLEMesh_Secure_Network_Beacon"):
            beacon = pkt.getlayer("BLEMesh_Secure_Network_Beacon")
            # print(f"收到安全网络 Beacon: Flag={beacon.Flag}, Network_ID={hex(beacon.Network_ID)}, IV_Index={beacon.IV_Index}")
            return pkt
        
        elif pkt.haslayer("BLEMesh_Mesh_Private_Beacon"):
            beacon = pkt.getlayer("BLEMesh_Mesh_Private_Beacon")
            # print(f"收到私有 Mesh Beacon")
            return pkt
        
        return pkt

    def send_beacon_handler(self, packet_name: str, pkt: Packet, field_name: list = None, field_value: list = None, handle_mode: str = "None"):
        """处理发送 Beacon 包"""
        
        
        if packet_name == "unprovisioned_device_beacon_pkt":
            # 处理未配网设备 Beacon
            if pkt.haslayer("BLEMesh_Unprovisioned_Device_Beacon"):
                pkt = self.restore_packet(pkt, field_name, field_value)
                return pkt
        
        elif packet_name == "secure_network_beacon_pkt":
            # 处理安全网络 Beacon
            if pkt.haslayer("BLEMesh_Secure_Network_Beacon") :
                beacon = pkt.getlayer("BLEMesh_Secure_Network_Beacon")

                pkt = self.restore_packet(pkt, field_name, field_value)
                beacon.Network_ID = self.mesh_decrypter.netkeys[0].NetworkID
                beacon.IV_Index = self.mesh_decrypter.netkeys[0].iv_index
                beacon.Auth_Value = self.mesh_decrypter.netkeys[0].auth_value_get(beacon.Flag, beacon.Network_ID, beacon.IV_Index)
                if handle_mode == "None":
                    return pkt
                else:
                    raw_pkt = self.packet_handle.handle_bytes(handle_mode,raw(pkt),random.randint(1,len(pkt)-6))
                    pkt = BTLE(raw_pkt)
                    return pkt
        
        elif packet_name == "mesh_private_beacon_pkt":
            # 处理私有 Mesh Beacon
            if pkt.haslayer("BLEMesh_Mesh_Private_Beacon"):
                pkt = self.restore_packet(pkt, field_name, field_value)
                return pkt
        
        return pkt

    def restore_packet(self, pkt: Packet, field_name: list = None, field_value: list = None):
        """恢复/设置包中的字段值"""
        if field_name is not None and field_value is not None:
            for i in range(len(field_name)):
                if not self._set_field_recursive(pkt, field_name[i], field_value[i]):
                    print(f"Error: {field_name[i]} is not in pkt")
        return pkt

    def _set_field_recursive(self, pkt, field_name, field_value):
        """递归查找并设置字段"""
        # 检查当前层的字段
        field_names = [field.name for field in pkt.fields_desc]
        if field_name in field_names:
            pkt.setfieldval(field_name, field_value)
            return True

        # 递归检查payload
        if hasattr(pkt, 'payload') and pkt.payload:
            if self._set_field_recursive(pkt.payload, field_name, field_value):
                return True

        return False