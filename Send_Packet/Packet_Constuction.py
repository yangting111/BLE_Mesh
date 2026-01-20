
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/libs/")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/libs/boofuzz/")


from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from scapy.contrib.ble_mesh import *
from scapy.all import Raw
from colorama import Fore
from Transfer.libs.ble_mesh_decrypter.ble_mesh_decrypter import MeshDecrypter
from Transfer.Send_Packet.Ble_Mesh_PBADV import Ble_Mesh_PBADV, Ble_Mesh_PBADV_Handler
from Transfer.Send_Packet.Ble_Mesh_Beacon import Ble_Mesh_Beacon, Ble_Mesh_Beacon_Handler
from Transfer.Send_Packet.Ble_Mesh_Message import Ble_Mesh_Message, Ble_Mesh_Message_Handler
from Transfer.libs.ble_mesh_decrypter.utils.key import NetworkKey, ApplicationKey, DeviceKey
from Transfer.libs.ble_mesh_decrypter.utils.kdf import KDF
import json


class Packet_Constuction():
    def __init__(self ,link_id ,advertiser_address ,rx_len ,tx_len ,key_path=None ,provisioned = False):
        self.link_id = link_id
        self.advertiser_address = advertiser_address
        self.pbadv_dict = {}
        self.beacon_dict = {}
        self.message_dict = {}

        self.kdf = KDF()
        self.mesh_decrypter = MeshDecrypter()
        self.pbadv = Ble_Mesh_PBADV(self.link_id, self.advertiser_address)
        self.beacon = Ble_Mesh_Beacon(self.advertiser_address)
        self.message = Ble_Mesh_Message(self.advertiser_address)
        self.pbadv_handle = Ble_Mesh_PBADV_Handler(self.link_id ,self.advertiser_address ,self.kdf ,self.mesh_decrypter,key_path)
        self.beacon_handle = Ble_Mesh_Beacon_Handler(self.mesh_decrypter)
        self.message_handle = Ble_Mesh_Message_Handler(advertiser_address=self.advertiser_address, mesh_decrypter=self.mesh_decrypter)
        self.rx_len = rx_len
        self.tx_len = tx_len
        self.encrypted = False
        self.key_path = key_path
        self.provisioned = provisioned
        if self.provisioned:
            with open(key_path, 'r') as f:
                data = json.load(f)
                
                self.network_key = NetworkKey(bytes.fromhex(data['netkeys'][0]['key']), int(data['netkeys'][0]['ivindex'], 16))
                self.device_key = DeviceKey(bytes.fromhex(data['devkeys'][0]['key']), data['devkeys'][0]['address'])
                self.application_key = ApplicationKey(bytes.fromhex(data['appkeys'][0]['key']))
                self.mesh_decrypter.set_appkey(self.application_key)
                self.mesh_decrypter.set_devkey(self.device_key)
                self.mesh_decrypter.set_netkey(self.network_key)

        if self.key_path and not self.provisioned:
            # 读取现有的 JSON 文件，更新 appkeys 字段
            if os.path.exists(key_path):
                # 备份旧文件
                old_file_path = key_path + '.old'
                if os.path.exists(old_file_path):
                    os.remove(old_file_path)
                os.rename(key_path, old_file_path)
                
            #     # 读取旧文件内容
            #     with open(old_file_path, 'r') as f:
            #         try:
            #             data = json.load(f)
            #         except json.JSONDecodeError:
            #             data = {}
                
            #     # 更新 appkeys
            #     data['appkeys'] = [{'key': self.application_key.key.hex()}]
                
            #     # 写入更新后的完整 JSON
            #     with open(key_path, 'w') as f:
            #         json.dump(data, f, indent=4)
            # else:
            #     # 如果文件不存在，只写入 appkeys
            #     with open(key_path, 'w') as f:
            #         json.dump({
            #             'appkeys': [{'key': self.application_key.key.hex()}]
            #         }, f, indent=4)

    def get_pkts(self ,pkt_list :list):
        pkt_type = pkt_list[0]
        pkts_list = {}
        if pkt_type == 'pbadv_pkts':
            for pkt in pkt_list[1:]:
                try:
                    pkts_list[pkt] = getattr(self.pbadv, pkt.upper().replace("_PKT", ""))()
                except AttributeError:
                    print(f"Error: {pkt} is not a valid packet type")
                self.pbadv_dict = pkts_list
        elif pkt_type == 'beacon_pkts':
            for pkt in pkt_list[1:]:
                try:
                    pkts_list[pkt] = getattr(self.beacon, pkt.upper().replace("_PKT", ""))()
                except AttributeError:
                    print(f"Error: {pkt} is not a valid packet type")
                self.beacon_dict = pkts_list
        elif pkt_type == 'message_pkts':
            for pkt in pkt_list[1:]:
                try:
                    pkts_list[pkt] = getattr(self.message, pkt.upper().replace("_PKT", ""))()
                except AttributeError:
                    print(f"Error: {pkt} is not a valid packet type")
                self.message_dict = pkts_list
        return pkts_list



    def set_pkts(self ,pkt_type :str ,data_list :list):

        if pkt_type == 'll_pkts':
            pkt_list = self.llpkt_dict
        elif pkt_type == 'adv_pkts':
            pkt_list = self.advpkt_dict
        elif pkt_type == 'smp_pkts':
            pkt_list = self.smppkt_dict
        elif pkt_type == 'l2cap_pkts':
            pkt_list = self.l2cappkt_dict
        elif pkt_type == 'att_pkts':
            pkt_list = self.attpkt_dict
        else:
            print(f"Error: {pkt_type} is not defined")
            return None
        #       [pkt,layer,field,value]
        for data in data_list:
            # print(data)
            if len(data ) <3:
                pass
            elif data[2 ]== 'raw':
                try:
                    pkt_list[data[0]] = pkt_list[data[0] ] /Raw(data[3])
                except AttributeError:
                    print(f"Error: {data[3]} is not a valid type, please input bytes value")
            else:
                try:
                    pkt_list[data[0]].getlayer(data[1]).setfieldval(data[2], data[3])
                except AttributeError:
                    print(f"Error: set_pkts failed")
        return pkt_list


    def get_pkt(self, pkt_name :str ,field_name :list =None ,field_value :list =None, handle_mode :str =None):
        print(Fore.YELLOW + "TX ---> " + pkt_name)
        # 如果两个list都不为空，则判断长度是否相等
        if field_name is not None and field_value is not None:
            if len(field_name) != len(field_value):
                print(f"Error: field_name and field_value have different lengths")
                return None

        if pkt_name in self.pbadv_dict:
            pkt = self.pbadv_dict[pkt_name]
            if isinstance(pkt, Packet):
                # print(f"field_name: {field_name}")
                # print(f"field_value: {field_value}")
                
                print(Fore.YELLOW + "TX ---> " +"|".join(pkt.summary().split(" / ")))
                back_pkt = self.pbadv_handle.send_pbadv_handler(pkt_name, pkt, field_name, field_value)
                return back_pkt
            else:
                print(f"Error: {pkt_name} is not defined")
                return None

        elif pkt_name in self.beacon_dict:
            pkt = self.beacon_dict[pkt_name]
            if isinstance(pkt, Packet):
                # print(Fore.YELLOW + "TX ---> " + "|".join(pkt.summary().split(" / ")))
                pkt = self.beacon_handle.send_beacon_handler(pkt_name, pkt, field_name, field_value, handle_mode)
                if pkt is not None:
                    print(Fore.YELLOW + "TX ---> " + "|".join(pkt.summary().split(" / ")))
                else:
                    print(f"Error: {pkt_name} is not defined")
                    return None
                return pkt
            else:
                print(f"Error: {pkt_name} is not defined")
                return None

        elif pkt_name in self.message_dict:
            pkt = self.message_dict[pkt_name]
            if isinstance(pkt, Packet):
                print(Fore.YELLOW + "TX ---> " + "|".join(pkt.summary().split(" / ")))
                back_pkt = self.message_handle.send_message_handler(pkt_name, pkt, field_name, field_value)
                return back_pkt
            else:
                print(f"Error: {pkt_name} is not defined")
                return None
        else:
            print(f"Error: {pkt_name} is not defined")
            return None

    def receive_packet_handler(self, pkt: Packet):
        if pkt.haslayer('BLEMesh_PBADV'):
            if pkt["BLEMesh_PBADV"].LinkId == self.link_id:
                # pkt.show2()
                pkt = self.pbadv_handle.receive_pbadv_handler(pkt)
                return pkt
        elif pkt.haslayer('BLEMesh_Beacon'):
            pkt = self.beacon_handle.receive_beacon_handler(pkt)
            return pkt
        elif pkt.haslayer('BLEMesh_Message'):
            pkt = self.message_handle.receive_message_handler(pkt)
            return pkt

    # def receive_packet_handler(self,pkt:Packet):
    #     decrypted = False

    #     if self.encrypted:
    #         print("aaaaaaaaaaa+Encrypted")
    #         result = self.ll_handle.receive_ll_handle(pkt)

    #         if isinstance(result, Packet):
    #             pkt = result
    #             decrypted = True

    #     if pkt.haslayer('BTLE_ADV'):

    #         result = self.adv_handle.receive_adv_handle(pkt)
    #     elif pkt.haslayer('BTLE_CTRL'):

    #         result = self.ll_handle.receive_ll_handle(pkt,decrypted)

    #         if isinstance(result, Packet) and result.haslayer('BTLE_CTRL'):
    #             if result.getlayer('BTLE_CTRL').getfieldval('opcode') == 0x06:
    #                 self.encrypted = True
    #             return result
    #         if isinstance(result, list):
    #             return result
    #     elif pkt.haslayer('BTLE_ATT'):

    #         result = self.att_handle.receive_att_handle(pkt)
    #     elif pkt.haslayer('L2CAP_CmdHdr'):

    #         result = self.l2cap_handle.receive_l2cap_handle(pkt)
    #     elif pkt.haslayer('SM_Hdr'):

    #         result = self.smp_handle.receive_smp_handle( pkt)
    #         return result
    #     else:
    #         return pkt

    # def send_packet_handler(self,pkt:Packet):

    #     if self.encrypted:
    #         print("aaaaaaaaaaa+Encrypted")
    #         packet = self.ll_handle.send_ll_handle(pkt)
    #         if isinstance(packet, Packet):
    #             result = self.packet_length_check(packet)
    #             return result

    #     if pkt.haslayer('BTLE_ADV'):

    #         result = self.adv_handle.send_adv_handle(pkt)

    #     elif pkt.haslayer('BTLE_CTRL'):
    #             ####test######
    #         if pkt.getlayer('BTLE_CTRL').getfieldval('opcode') == 0x06:

    #             self.encrypted = True
    #             ####test######

    #         packet = self.ll_handle.send_ll_handle(pkt)
    #         if isinstance(packet, Packet):
    #             result = self.packet_length_check(packet)
    #             return result
    #     elif pkt.haslayer('ATT_Hdr'):

    #         packet = self.att_handle.send_att_handle(pkt)

    #     elif pkt.haslayer('L2CAP_CmdHdr'):

    #         packet = self.l2cap_handle.send_l2cap_handle(pkt)

    #     elif pkt.haslayer('SM_Hdr'):

    #         packet = self.smp_handle.send_smp_handle(pkt)
    #         if isinstance(packet, Packet):
    #             result = self.packet_length_check(packet)
    #             return result
    #     else:
    #         result = None

    # def find_section(self, packet_name:str):
    #     if packet_name in list(self.advpkt_dict.keys()):
    #         return 'adv_pkts'
    #     elif packet_name in list(self.llpkt_dict.keys()):
    #         return 'll_pkts'
    #     elif packet_name in list(self.smppkt_dict.keys()):
    #         return 'smp_pkts'
    #     elif packet_name in list(self.l2cappkt_dict.keys()):
    #         return 'l2cap_pkts'
    #     elif packet_name in list(self.attpkt_dict.keys()):
    #         return 'att_pkts'
    #     else:
    #         return None

    # def set_encryption(self,encrypted:bool):
    #     self.encrypted = encrypted
    #     self.ll_enc.ll_encryption = encrypted

    # def packet_length_check(self,pkt:Packet):
    #     # pkt.show2()
    #     if pkt.haslayer('L2CAP_Hdr'):
    #         l2cap_pkt = pkt.getlayer("L2CAP_Hdr")
    #         if len(raw(l2cap_pkt)) > self.tx_len:
    #             pkt_list = self.pkt_fragment(l2cap_pkt)
    #             return pkt_list
    #         else:
    #             return pkt
    #     else:
    #         return pkt

    # def pkt_fragment(self,pkt) -> List[Packet]:
    #     p = pkt
    #     lst =[]
    #     total_len = len(raw(p))
    #     nb = total_len//self.tx_len + 1
    #     for i in range(nb):
    #         if i == 0:
    #             f = BTLE() / BTLE_DATA(LLID = 0x02,SN = 1,NESN = 1, MD = 1)/raw(p)[0:(self.tx_len)]
    #         elif i == nb-1:
    #             f = BTLE() / BTLE_DATA(LLID = 0x01,SN = 1,NESN = 1)/raw(p)[self.tx_len+(i-1)*(self.tx_len):]
    #         else:
    #             f = BTLE() / BTLE_DATA(LLID = 0x01,SN = 0,NESN = 0, MD =1)/raw(p)[(i)*(self.tx_len):(i+1)*(self.tx_len)]
    #         lst.append(f)
    #     return lst
    # def pkt_reassemble(self,pkt_list:List[Packet]) -> Packet:
    #     p = pkt_list[0]
    #     for i in range(1,len(pkt_list)):
    #         p = p/pkt_list[i].getlayer('BTLE_DATA')
    #     return p

    # def save_key(self):
    #     if self.key_path:

    #         key1 = self.ll_enc.__dict__
    #         key2 = self.sm.__dict__
    #         with open(self.key_path, 'a') as f:
    #             f.write("LL_ENC\n")
    #             f.write("-------------------------------------------\n")
    #             for key, value in key1.items():
    #                 if isinstance(value, bytes):
    #                     f.write(f"{key}: {value.hex()}\n")
    #                 elif isinstance(value, int) or isinstance(value, str):
    #                     f.write(f"{key}: {value}\n")
    #                 elif value is None:
    #                     f.write(f"{key}: None\n")
    #                 else:
    #                     pass

    #             f.write("SM\n")
    #             f.write("-------------------------------------------\n")
    #             for key, value in key2.items():
    #                 if isinstance(value, bytes):
    #                     f.write(f"{key}: {value.hex()}\n")
    #                 elif isinstance(value, int) or isinstance(value, str):
    #                     f.write(f"{key}: {value}\n")
    #                 elif value is None:
    #                     f.write(f"{key}: None\n")
    #                 else:
    #                     pass
    #             f.write("-------------------------------------------\n")


