import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/../../")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/../libs/")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/../libs/boofuzz/")

from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from scapy.packet import Packet, raw, Raw
import json
from scapy.contrib.ble_mesh import *
from scapy.utils import *
from Transfer.libs.ble_mesh_decrypter.utils.kdf import KDF
from Transfer.libs.ble_mesh_decrypter.utils.key import NetworkKey, ApplicationKey, DeviceKey
from Transfer.libs.ble_mesh_decrypter.ble_mesh_decrypter import MeshDecrypter
from Transfer.Send_Packet.packet_factory import (
    create_link_open,
    create_link_ack,
    create_link_close,
    create_transaction_acknowledgment,
    create_provisioning_invite,
    create_provisioning_capabilities,
    create_provisioning_start,
    create_provisioning_public_key,
    create_provisioning_confirmation,
    create_provisioning_random,
    create_provisioning_data,
    create_provisioning_complete,
    create_provisioning_failed
)

# 配网PDU类型 (规范5.4.1节)
PROVISIONING_INVITE = 0x00
PROVISIONING_CAPABILITIES = 0x01
PROVISIONING_START = 0x02
PROVISIONING_PUBLIC_KEY = 0x03
PROVISIONING_INPUT_COMPLETE = 0x04
PROVISIONING_CONFIRMATION = 0x05
PROVISIONING_RANDOM = 0x06
PROVISIONING_DATA = 0x07
PROVISIONING_COMPLETE = 0x08
PROVISIONING_FAILED = 0x09


class Ble_Mesh_PBADV():
    def __init__(self, link_id: int, advertiser_address: str):
        self.name = "ble_mesh_pbadv"
        self.advertiser_address = advertiser_address
        self.link_id = link_id

    def LINK_OPEN_MESSAGE(self):
        pkt = create_link_open()
        if pkt.haslayer("BLEMesh_PBADV"):
            pkt["BLEMesh_PBADV"].LinkId = self.link_id
        pkt["BTLE_ADV_NONCONN_IND"].AdvA = self.advertiser_address
        return pkt

    def LINK_ACK_MESSAGE(self):
        pkt = create_link_ack()
        if pkt.haslayer("BLEMesh_PBADV"):
            pkt["BLEMesh_PBADV"].LinkId = self.link_id
        pkt["BTLE_ADV_NONCONN_IND"].AdvA = self.advertiser_address
        return pkt

    def LINK_CLOSE_MESSAGE(self):
        pkt = create_link_close()
        if pkt.haslayer("BLEMesh_PBADV"):
            pkt["BLEMesh_PBADV"].LinkId = self.link_id
        pkt["BTLE_ADV_NONCONN_IND"].AdvA = self.advertiser_address
        return pkt

    def TRANSACTION_ACKNOWLEDGMENT(self):
        pkt = create_transaction_acknowledgment()
        if pkt.haslayer("BLEMesh_PBADV"):
            pkt["BLEMesh_PBADV"].LinkId = self.link_id
        pkt["BTLE_ADV_NONCONN_IND"].AdvA = self.advertiser_address
        return pkt

    def PROVISIONING_INVITE(self):
        pkt = create_provisioning_invite()
        return pkt

    def PROVISIONING_CAPABILITY(self):
        pkt = create_provisioning_capabilities()
        return pkt

    def PROVISIONING_START(self):
        pkt = create_provisioning_start()
        return pkt

    def PROVISIONING_PUBLIC_KEY(self):
        pkt = create_provisioning_public_key()
        return pkt

    def PROVISIONING_CONFIRMATION(self):
        pkt = create_provisioning_confirmation()
        return pkt

    def PROVISIONING_RANDOM(self):
        pkt = create_provisioning_random()
        return pkt

    def PROVISIONING_DATA(self):
        pkt = create_provisioning_data()
        return pkt

    def PROVISIONING_COMPLETE(self):
        pkt = create_provisioning_complete()
        return pkt

    def PROVISIONING_FAILED(self):
        pkt = create_provisioning_failed()
        return pkt


class Ble_Mesh_PBADV_Handler():
    def __init__(self, link_id, advertiser_address: str, kdf: KDF, mesh_decrypter: MeshDecrypter, key_path: str):
        self.device_uuid = None
        self.link_id = link_id
        self.advertiser_address = advertiser_address
        self.transaction_number = 0
        self.received_transaction_number = 0
        self.plist = []
        self.last_pkt = 0
        self.algorithm = 0
        self.kdf = kdf
        self.mesh_decrypter = mesh_decrypter
        self.provisioning_params = {'publickeyprovisionerx': b'',
                                    'publickeyprovisionery': b'',
                                    'privatekey': b'',
                                    'publickeydevicex': b'',
                                    'publickeydevicey': b'',
                                    'confirmationinputs': b'',
                                    'confirmationsalt': b'',
                                    'randomprovisioner': b'',
                                    'randomdevice': b'',
                                    'ecdhsecret': b'',
                                    'authvalue': b'',
                                    'appkey': b'',
                                    'devkey': b'',
                                    'netkey': b'',
                                    'iv_index': b'',
                                    }
        self.key_information = {'netkey': b'', 'devkey': b'', 'appkey': b''}
        self.received_CRC_list = []
        self.received_FCS_list = []
        self.received_segment_index_list = []
        self.key_path = key_path
    def get_device_uuid(self):
        return self.device_uuid

    def set_device_uuid(self, device_uuid):
        self.device_uuid = device_uuid

    def get_link_id(self):
        return self.link_id

    def set_link_id(self, link_id):
        self.link_id = link_id

    def receive_pbadv_handler(self, pkt: Packet):
        # 根据ble crc判断是否为接收过的数据包
        if pkt["BTLE"].crc in self.received_CRC_list:
            return None
        else:
            self.received_CRC_list.append(pkt["BTLE"].crc)

        if pkt.haslayer("Transaction_Start_PDU"):
            if (pkt["BLEMesh_PBADV"].TransNum,pkt["Transaction_Start_PDU"].FCS) in self.received_FCS_list:
                return None
            else:
                self.received_FCS_list.append((pkt["BLEMesh_PBADV"].TransNum,pkt["Transaction_Start_PDU"].FCS))

        if pkt.haslayer("Transaction_Continuation_PDU"):
            if (pkt["BLEMesh_PBADV"].TransNum,pkt["Transaction_Continuation_PDU"].SegmentIndex) in self.received_segment_index_list:
                return None
            else:
                self.received_segment_index_list.append((pkt["BLEMesh_PBADV"].TransNum,pkt["Transaction_Continuation_PDU"].SegmentIndex))


        re_pkt = None
        if pkt.haslayer("Link_Open_Message"):
            return pkt
        elif pkt.haslayer("Link_ACK_Message"):
            return pkt
        elif pkt.haslayer("Link_Close_Message"):
            return pkt
        elif pkt.haslayer("Transaction_Start_PDU"):

            self.last_pkt = pkt["Transaction_Start_PDU"].SegN
            if self.last_pkt == 0:
                raw_pkt = raw(pkt["Transaction_Start_PDU"].payload)
                re_pkt = BLEMesh_Provisioning_PDU(raw_pkt)
            else:
                # print(f"Transaction_Start_PDU:--------------------------------")
                self.plist.append(pkt.copy())
        elif pkt.haslayer("Transaction_Continuation_PDU"):
            # print(f"Transaction_Continuation_PDU: --------------------------------")
            self.plist.append(pkt.copy())
            if pkt["Transaction_Continuation_PDU"].SegmentIndex == self.last_pkt:
                re_pkt = self.defragment(self.plist)
                # re_pkt = PBAdvPDU(transaction_number=pkt["PBAdvPDU"].transaction_number) /pkt1.getlayer('ProvisioningPDU')
        elif pkt.haslayer("Transaction_Acknowledgment_PDU"):
            return pkt
        else:
            return pkt

        if re_pkt is not None:
            self.received_transaction_number = pkt["BLEMesh_PBADV"].TransNum

            if re_pkt.getlayer('BLEMesh_Provisioning_PDU').PDU_Type == PROVISIONING_INVITE:
                pass
            elif re_pkt.getlayer('BLEMesh_Provisioning_PDU').PDU_Type == PROVISIONING_CAPABILITIES:
                self.provisioning_params['confirmationinputs'] += raw(re_pkt.getlayer('Provisioning_Capabilities'))
                # print(self.provisioning_params)
            elif re_pkt.getlayer('BLEMesh_Provisioning_PDU').PDU_Type == PROVISIONING_START:
                pass
            elif re_pkt.getlayer('BLEMesh_Provisioning_PDU').PDU_Type == PROVISIONING_PUBLIC_KEY:
                self.provisioning_params['publickeydevicex'] = re_pkt.getlayer('Provisioning_Public_Key').PublicKeyX
                self.provisioning_params['publickeydevicey'] = re_pkt.getlayer('Provisioning_Public_Key').PublicKeyY
                self.provisioning_params['confirmationinputs'] += self.provisioning_params['publickeydevicex']
                self.provisioning_params['confirmationinputs'] += self.provisioning_params['publickeydevicey']
                # re_pkt.show2()
            elif re_pkt.getlayer('BLEMesh_Provisioning_PDU').PDU_Type == PROVISIONING_INPUT_COMPLETE:
                pass
            elif re_pkt.getlayer('BLEMesh_Provisioning_PDU').PDU_Type == PROVISIONING_CONFIRMATION:
                # re_pkt.show()
                pass
            elif re_pkt.getlayer('BLEMesh_Provisioning_PDU').PDU_Type == PROVISIONING_RANDOM:
                self.provisioning_params['randomdevice'] = re_pkt.getlayer('Provisioning_Random').Random

            elif re_pkt.getlayer('BLEMesh_Provisioning_PDU').PDU_Type == PROVISIONING_DATA:
                pass
            elif re_pkt.getlayer('BLEMesh_Provisioning_PDU').PDU_Type == PROVISIONING_COMPLETE:
                pass
            elif re_pkt.getlayer('BLEMesh_Provisioning_PDU').PDU_Type == PROVISIONING_FAILED:
                pass
            return re_pkt

    def send_pbadv_handler(self, packet_name, pkt: Packet, field_name: list = None, field_value: list = None):

        if packet_name == "link_open_message_pkt":
            pkt["Link_Open_Message"].Device_UUID = self.get_device_uuid()
            pkt = self.restore_packet(pkt, field_name, field_value)
        elif packet_name == "link_ack_message_pkt":
            # pkt["PBAdvPDU"].transaction_number = self.received_transaction_number
            pkt = self.restore_packet(pkt, field_name, field_value)
        elif packet_name == "link_close_message_pkt":
            pkt = self.restore_packet(pkt, field_name, field_value)
        elif packet_name == "provisioning_invite_pkt":
            self.transaction_number = 0
            if pkt.haslayer("Provisioning_Invite"):
                pkt.getlayer("Provisioning_Invite").ATTENTION_DURATION = 0x05
            pkt = self.restore_packet(pkt, field_name, field_value)
            if pkt.haslayer("Provisioning_Invite"):
                self.provisioning_params['confirmationinputs'] = raw(pkt.getlayer('Provisioning_Invite'))
            pktlist = self.fragment(pkt)
            return pktlist
        elif packet_name == "provisioning_capability_pkt":
            self.transaction_number += 1
            pkt = self.restore_packet(pkt, field_name, field_value)
            pktlist = self.fragment(pkt)
            return pktlist
        elif packet_name == "provisioning_start_pkt":
            self.transaction_number += 1
            pkt = self.restore_packet(pkt, field_name, field_value)
            # self.algorithm = pkt.getlayer('Provisioning_Start').Algorithm & 0b00000001
            print(f"algorithm: {self.algorithm}")
            self.kdf.set_algorithm(self.algorithm)
            pkt.getlayer('Provisioning_Start').Algorithm = self.algorithm
            self.provisioning_params['confirmationinputs'] += raw(pkt.getlayer('Provisioning_Start'))
            pktlist = self.fragment(pkt)
            return pktlist
        elif packet_name == "provisioning_public_key_pkt":
            self.transaction_number += 1
            key_set = self.kdf.ecc_generate_key()
            self.provisioning_params['publickeyprovisionerx'] = key_set['public_key_x']
            self.provisioning_params['publickeyprovisionery'] = key_set['public_key_y']
            self.provisioning_params['privatekey'] = key_set['private_key']
            self.provisioning_params['confirmationinputs'] += key_set['public_key_x']
            self.provisioning_params['confirmationinputs'] += key_set['public_key_y']
            # raw_data = "4f55298c47d295d26e91a43349eec8fa1a524e92e8678634dc225989bbea1b2633b2873420b961c697c7234f8d605a31b779f87d94505c69c3dec279fea5b937"
            # raw_data = bytes.fromhex(raw_data)
            # key_set['public_key_x'] = raw_data[0:32]
            # key_set['public_key_y'] = raw_data[32:64]
            pkt.getlayer('Provisioning_Public_Key').PublicKeyX = key_set['public_key_x']
            pkt.getlayer('Provisioning_Public_Key').PublicKeyY = key_set['public_key_y']
            pkt = self.restore_packet(pkt, field_name, field_value)
            pktlist = self.fragment(pkt)
            return pktlist
        elif packet_name == "provisioning_confirmation_pkt":
            self.transaction_number += 1
            self.provisioning_params['confirmationsalt'] = self.kdf.get_confirmationsalt(
                self.provisioning_params['confirmationinputs'])
            self.provisioning_params['ecdhsecret'] = self.kdf.gen_ECDHSecretKey(self.provisioning_params['privatekey'],
                                                                                self.provisioning_params[
                                                                                    'publickeydevicex'],
                                                                                self.provisioning_params[
                                                                                    'publickeydevicey'])
            self.provisioning_params['randomprovisioner'] = self.kdf.get_random_provisioning()
            if self.algorithm == 0:
                self.provisioning_params['authvalue'] = b'\x00' * 16
            elif self.algorithm == 1:
                self.provisioning_params['authvalue'] = b'\x00' * 32
            # self.provisioning_params['authvalue'] = b'\x00' * 32
            # print(self.provisioning_params)
            ConfirmationValue = self.kdf.get_confirmation_value(self.provisioning_params['confirmationsalt'],
                                                                self.provisioning_params['ecdhsecret'],
                                                                self.provisioning_params['randomprovisioner'],
                                                                self.provisioning_params['authvalue'])
            pkt.getlayer("Provisioning_Confirmation").Confirmation = ConfirmationValue
            # print(f"ConfirmationValue长度: {len(ConfirmationValue)}")
            pkt = self.restore_packet(pkt, field_name, field_value)
            pktlist = self.fragment(pkt)
            return pktlist
        elif packet_name == "provisioning_random_pkt":
            self.transaction_number += 1
            pkt.getlayer('Provisioning_Random').Random = self.provisioning_params['randomprovisioner']
            pkt = self.restore_packet(pkt, field_name, field_value)
            pktlist = self.fragment(pkt)
            return pktlist
        elif packet_name == "provisioning_data_pkt":
            self.transaction_number += 1
            # Calculate Provisioning Salt using the KDF function
            # This calls s1(ConfirmationSalt || RandomProvisioner || RandomDevice) and returns 16 bytes
            provisioning_salt = self.kdf.get_provisioning_salt(
                self.provisioning_params['confirmationsalt'],
                self.provisioning_params['randomprovisioner'],
                self.provisioning_params['randomdevice']
            )
            # print(f"Provisioning Salt: {provisioning_salt.hex()} (length: {len(provisioning_salt)} bytes)")
            
            self.key_information['newkey'] = self.kdf.get_random(16)
            network_key = NetworkKey(self.key_information['newkey'], 0)
            ProvisioningData = raw(
                Provisioning_Data_Unencrypted(NetworkKey=self.key_information['newkey'], KeyIndex=0x00, Flags=0x00,
                                            IVIndex=0x00000000, UnicastAddress=0x0005))
            EncryptedProvisioningData, ProvisioningDataMIC = self.kdf.get_provisioning_data(provisioning_salt, ecdh_secret=self.provisioning_params['ecdhsecret'], provisioning_data=ProvisioningData)
            self.key_information['devkey'] = self.kdf.k1(self.provisioning_params['ecdhsecret'], provisioning_salt, "prdk")
            device_key = DeviceKey(self.key_information['devkey'], 0x0005)
            appkey = ApplicationKey(bytes.fromhex('12121212121212121212121212121212'))
            # print(self.key_path)
            with open(self.key_path, 'w') as f:
                json.dump({
                    'AdvA': self.advertiser_address,
                    'netkeys': [{'key': network_key.key.hex(), 'ivindex': hex(network_key.iv_index)}],
                    'devkeys': [{'key': device_key.key.hex(), 'address': device_key.address}],
                    'appkeys': [{'key': appkey.key.hex()}] 
                }, f, indent=4)
            self.mesh_decrypter.set_devkey(device_key)
            self.mesh_decrypter.set_netkey(network_key)
            print("network_key:", network_key.key.hex())
            self.mesh_decrypter.set_appkey(appkey)
            pkt.getlayer('Provisioning_Data').EncryptedData = EncryptedProvisioningData
            pkt.getlayer('Provisioning_Data').MIC = ProvisioningDataMIC
            pkt = self.restore_packet(pkt, field_name, field_value)
            pktlist = self.fragment(pkt)
            return pktlist
        elif packet_name == "transaction_acknowledgment_pkt":
            if pkt.haslayer("BLEMesh_PBADV"):
                pkt.getlayer("BLEMesh_PBADV").TransNum = self.received_transaction_number
            return pkt

        elif packet_name == "provisioning_complete_pkt":
            pktlist = self.fragment(pkt)
            return pktlist
        return pkt

    def fragment(self, pkt: Packet, fragsize=24):
        """Fragment a big PB-ADV datagram"""
        p = pkt
        lst = []
        if not p.haslayer('BLEMesh_Provisioning_PDU'):
            return p
        total_len = len(raw(p.getlayer('BLEMesh_Provisioning_PDU')))
        nb = total_len // fragsize
        for i in range(nb + 1):
            if i == 0:
                # 对于第一个片段，如果包含完整的ProvisioningPDU，直接使用原始的PDU对象而不是转换为raw字节
                prov_pdu_raw = raw(p.getlayer('BLEMesh_Provisioning_PDU'))
                if total_len <= (fragsize - 4):
                    # 如果完整的ProvisioningPDU可以放入第一个片段，直接使用原始PDU对象
                    payload = p.getlayer('BLEMesh_Provisioning_PDU')
                else:
                    # 如果需要分片，则使用原始字节
                    payload = prov_pdu_raw[0:(fragsize - 4)]
                f = BTLE() / BTLE_ADV() / BTLE_ADV_NONCONN_IND(AdvA=self.advertiser_address) / EIR_Hdr() / BLEMesh_PBADV(
                    LinkId=self.link_id, TransNum=self.transaction_number) / Transaction_Start_PDU(SegN=nb, GPCF=0,
                                                                                                  len=total_len,
                                                                                                  FCS=crc8(
                                                                                                      prov_pdu_raw)) / payload
            elif i == nb:
                payload = raw(p.getlayer('BLEMesh_Provisioning_PDU'))[(fragsize - 4) + (i - 1) * (fragsize - 1):]
                f = BTLE() / BTLE_ADV() / BTLE_ADV_NONCONN_IND(AdvA=self.advertiser_address) / EIR_Hdr() / BLEMesh_PBADV(
                    LinkId=self.link_id, TransNum=self.transaction_number) / Transaction_Continuation_PDU(
                    SegmentIndex=i, GPCF=2) / payload
            else:
                payload = raw(p.getlayer('BLEMesh_Provisioning_PDU'))[(fragsize - 4) + (i - 1) * (fragsize - 1):
                                                                      i * (fragsize - 1) + (fragsize - 4)]
                f = BTLE() / BTLE_ADV() / BTLE_ADV_NONCONN_IND(AdvA=self.advertiser_address) / EIR_Hdr() / BLEMesh_PBADV(
                    LinkId=self.link_id, TransNum=self.transaction_number) / Transaction_Continuation_PDU(
                    SegmentIndex=i, GPCF=2) / payload
            lst.append(f)
        self.plist = []
        return lst

    def defragment(self, plist):
        """defragment PB-ADV datagrams"""
        PDU = bytes()
        for p in plist:
            if p.haslayer("Transaction_Start_PDU"):
                PDU += raw(p["Transaction_Start_PDU"].payload)
            elif p.haslayer("Transaction_Continuation_PDU"):
                PDU += raw(p["Transaction_Continuation_PDU"].payload)
        packet = BLEMesh_Provisioning_PDU(PDU)
        # packet.show2()
        return packet

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

