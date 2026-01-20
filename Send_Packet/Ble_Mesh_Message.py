import random
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/../../")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/../libs/")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/../libs/boofuzz/")


from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from scapy.packet import raw, Raw
from scapy.contrib.ble_mesh import *
from Transfer.libs.ble_mesh_decrypter.ble_mesh_decrypter import MeshDecrypter
from scapy.all import hexdump
from Transfer.Send_Packet.packet_handle import Packet_Handle
from Transfer.Send_Packet.packet_factory import (
    create_config_beacon_get,
    create_config_beacon_set,
    create_config_beacon_status,
    create_config_composition_data_get,
    create_config_default_ttl_get,
    create_config_default_ttl_set,
    create_config_default_ttl_status,
    create_config_gatt_proxy_get,
    create_config_gatt_proxy_set,
    create_config_gatt_proxy_status,
    create_config_relay_get,
    create_config_relay_set,
    create_config_relay_status,
    create_config_model_publication_get,
    create_config_model_publication_set,
    create_config_model_publication_virtual_address_set,
    create_config_model_publication_status,
    create_config_model_subscription_add,
    create_config_model_subscription_virtual_address_add,
    create_config_model_subscription_delete,
    create_config_model_subscription_virtual_address_delete,
    create_config_model_subscription_overwrite,
    create_config_model_subscription_virtual_address_overwrite,
    create_config_model_subscription_status,
    create_config_sig_model_subscription_get,
    create_config_sig_model_subscription_list,
    create_config_vendor_model_subscription_get,
    create_config_vendor_model_subscription_list,
    create_config_netkey_add,
    create_config_netkey_update,
    create_config_netkey_delete,
    create_config_netkey_status,
    create_config_netkey_get,
    create_config_netkey_list,
    create_config_app_key_add,
    create_config_app_key_update,
    create_config_app_key_delete,
    create_config_app_key_status,
    create_config_app_key_get,
    create_config_app_key_list,
    create_config_node_identity_get,
    create_config_node_identity_set,
    create_config_node_identity_status,
    create_config_model_app_bind,
    create_config_model_app_status,
    create_config_model_app_unbind,
    create_config_sig_model_app_get,
    create_config_sig_model_app_list,
    create_config_vendor_model_app_get,
    create_config_vendor_model_app_list,
    create_config_node_reset,
    create_config_node_reset_status,
    create_config_friend_get,
    create_config_friend_set,
    create_config_friend_status,
    create_config_key_refresh_phase_get,
    create_config_key_refresh_phase_set,
    create_config_key_refresh_phase_status,
    create_config_heartbeat_publication_get,
    create_config_heartbeat_publication_set,
    create_config_heartbeat_publication_status,
    create_config_heartbeat_subscription_get,
    create_config_heartbeat_subscription_set,
    create_config_heartbeat_subscription_status,
    create_config_low_power_node_poll_timeout_get,
    create_config_low_power_node_poll_timeout_status,
    create_config_network_transmit_get,
    create_config_network_transmit_set,
    create_config_network_transmit_status,
    create_segment_ack,
    create_generic_onoff_get
)


class Ble_Mesh_Message():
    def __init__(self, advertiser_address: str):
        self.name = "ble_mesh_message"
        self.advertiser_address = advertiser_address

    def CONFIG_BEACON_GET(self):
        pkt = create_config_beacon_get()
        # pkt.show()
        return pkt

    def CONFIG_BEACON_SET(self):
        pkt = create_config_beacon_set()
        return pkt

    def CONFIG_BEACON_STATUS(self):
        pkt = create_config_beacon_status()
        return pkt

    def CONFIG_COMPOSITION_DATA_GET(self):
        pkt = create_config_composition_data_get()
        return pkt

    def CONFIG_DEFAULT_TTL_GET(self):
        pkt = create_config_default_ttl_get()
        return pkt

    def CONFIG_DEFAULT_TTL_SET(self):
        pkt = create_config_default_ttl_set()
        return pkt

    def CONFIG_DEFAULT_TTL_STATUS(self):
        pkt = create_config_default_ttl_status()
        return pkt

    def CONFIG_GATT_PROXY_GET(self):
        pkt = create_config_gatt_proxy_get()
        return pkt

    def CONFIG_GATT_PROXY_SET(self):
        pkt = create_config_gatt_proxy_set()
        return pkt

    def CONFIG_GATT_PROXY_STATUS(self):
        pkt = create_config_gatt_proxy_status()
        return pkt

    def CONFIG_RELAY_GET(self):
        pkt = create_config_relay_get()
        return pkt

    def CONFIG_RELAY_SET(self):
        pkt = create_config_relay_set()
        return pkt

    def CONFIG_RELAY_STATUS(self):
        pkt = create_config_relay_status()
        return pkt

    def CONFIG_MODEL_PUBLICATION_GET(self):
        pkt = create_config_model_publication_get()
        return pkt

    def CONFIG_MODEL_PUBLICATION_SET(self):
        pkt = create_config_model_publication_set()
        return pkt

    def CONFIG_MODEL_PUBLICATION_VIRTUAL_ADDRESS_SET(self):
        pkt = create_config_model_publication_virtual_address_set()
        return pkt

    def CONFIG_MODEL_PUBLICATION_STATUS(self):
        pkt = create_config_model_publication_status()
        return pkt

    def CONFIG_MODEL_SUBSCRIPTION_ADD(self):
        pkt = create_config_model_subscription_add()
        return pkt

    def CONFIG_MODEL_SUBSCRIPTION_VIRTUAL_ADDRESS_ADD(self):
        pkt = create_config_model_subscription_virtual_address_add()
        return pkt

    def CONFIG_MODEL_SUBSCRIPTION_DELETE(self):
        pkt = create_config_model_subscription_delete()
        return pkt

    def CONFIG_MODEL_SUBSCRIPTION_VIRTUAL_ADDRESS_DELETE(self):
        pkt = create_config_model_subscription_virtual_address_delete()
        return pkt

    def CONFIG_MODEL_SUBSCRIPTION_OVERWRITE(self):
        pkt = create_config_model_subscription_overwrite()
        return pkt

    def CONFIG_MODEL_SUBSCRIPTION_VIRTUAL_ADDRESS_OVERWRITE(self):
        pkt = create_config_model_subscription_virtual_address_overwrite()
        return pkt
        return pkt

    def CONFIG_MODEL_SUBSCRIPTION_STATUS(self):
        pkt = create_config_model_subscription_status()
        return pkt

    def CONFIG_SIG_MODEL_SUBSCRIPTION_GET(self):
        pkt = create_config_sig_model_subscription_get()
        return pkt

    def CONFIG_SIG_MODEL_SUBSCRIPTION_LIST(self):
        pkt = create_config_sig_model_subscription_list()
        return pkt

    def CONFIG_VENDOR_MODEL_SUBSCRIPTION_GET(self):
        pkt = create_config_vendor_model_subscription_get()
        return pkt

    def CONFIG_VENDOR_MODEL_SUBSCRIPTION_LIST(self):
        pkt = create_config_vendor_model_subscription_list()
        return pkt

    def CONFIG_NETKEY_ADD(self):
        pkt = create_config_netkey_add()
        return pkt

    def CONFIG_NETKEY_UPDATE(self):
        pkt = create_config_netkey_update()
        return pkt

    def CONFIG_NETKEY_DELETE(self):
        pkt = create_config_netkey_delete()
        return pkt

    def CONFIG_NETKEY_STATUS(self):
        pkt = create_config_netkey_status()
        return pkt

    def CONFIG_NETKEY_GET(self):
        pkt = create_config_netkey_get()
        return pkt

    def CONFIG_NETKEY_LIST(self):
        pkt = create_config_netkey_list()
        return pkt

    def CONFIG_APP_KEY_ADD(self):
        pkt = create_config_app_key_add()
        return pkt

    def CONFIG_APP_KEY_UPDATE(self):
        pkt = create_config_app_key_update()
        return pkt

    def CONFIG_APP_KEY_DELETE(self):
        pkt = create_config_app_key_delete()
        return pkt

    def CONFIG_APP_KEY_STATUS(self):
        pkt = create_config_app_key_status()
        return pkt

    def CONFIG_APP_KEY_GET(self):
        pkt = create_config_app_key_get()
        return pkt

    def CONFIG_APP_KEY_LIST(self):
        pkt = create_config_app_key_list()
        return pkt

    def CONFIG_NODE_IDENTITY_GET(self):
        pkt = create_config_node_identity_get()
        return pkt

    def CONFIG_NODE_IDENTITY_SET(self):
        pkt = create_config_node_identity_set()
        return pkt

    def CONFIG_NODE_IDENTITY_STATUS(self):
        pkt = create_config_node_identity_status()
        return pkt

    def CONFIG_MODEL_APP_BIND(self):
        pkt = create_config_model_app_bind()

        # pkt.show2()
        return pkt

    def CONFIG_MODEL_APP_STATUS(self):
        pkt = create_config_model_app_status()
        return pkt

    def CONFIG_MODEL_APP_UNBIND(self):
        pkt = create_config_model_app_unbind()
        return pkt

    def CONFIG_SIG_MODEL_APP_GET(self):
        pkt = create_config_sig_model_app_get()
        return pkt

    def CONFIG_SIG_MODEL_APP_LIST(self):
        pkt = create_config_sig_model_app_list()
        return pkt

    def CONFIG_VENDOR_MODEL_APP_GET(self):
        pkt = create_config_vendor_model_app_get()
        return pkt

    def CONFIG_VENDOR_MODEL_APP_LIST(self):
        pkt = create_config_vendor_model_app_list()
        return pkt

    def CONFIG_NODE_RESET(self):
        pkt = create_config_node_reset()
        return pkt

    def CONFIG_NODE_RESET_STATUS(self):
        pkt = create_config_node_reset_status()
        return pkt

    def CONFIG_FRIEND_GET(self):
        pkt = create_config_friend_get()
        return pkt

    def CONFIG_FRIEND_SET(self):
        pkt = create_config_friend_set()
        return pkt

    def CONFIG_FRIEND_STATUS(self):
        pkt = create_config_friend_status()
        return pkt

    def CONFIG_KEY_REFRESH_PHASE_GET(self):
        pkt = create_config_key_refresh_phase_get()
        return pkt

    def CONFIG_KEY_REFRESH_PHASE_SET(self):
        pkt = create_config_key_refresh_phase_set()
        return pkt

    def CONFIG_KEY_REFRESH_PHASE_STATUS(self):
        pkt = create_config_key_refresh_phase_status()
        return pkt

    def CONFIG_HEARTBEAT_PUBLICATION_GET(self):
        pkt = create_config_heartbeat_publication_get()
        return pkt

    def CONFIG_HEARTBEAT_PUBLICATION_SET(self):
        pkt = create_config_heartbeat_publication_set()
        return pkt

    def CONFIG_HEARTBEAT_PUBLICATION_STATUS(self):
        pkt = create_config_heartbeat_publication_status()
        return pkt

    def CONFIG_HEARTBEAT_SUBSCRIPTION_GET(self):
        pkt = create_config_heartbeat_subscription_get()
        return pkt

    def CONFIG_HEARTBEAT_SUBSCRIPTION_SET(self):
        pkt = create_config_heartbeat_subscription_set()
        return pkt

    def CONFIG_HEARTBEAT_SUBSCRIPTION_STATUS(self):
        pkt = create_config_heartbeat_subscription_status()
        return pkt

    def CONFIG_LOW_POWER_NODE_POLL_TIMEOUT_GET(self):
        pkt = create_config_low_power_node_poll_timeout_get()
        return pkt

    def CONFIG_LOW_POWER_NODE_POLL_TIMEOUT_STATUS(self):
        pkt = create_config_low_power_node_poll_timeout_status()
        return pkt

    def CONFIG_NETWORK_TRANSMIT_GET(self):
        pkt = create_config_network_transmit_get()
        return pkt

    def CONFIG_NETWORK_TRANSMIT_SET(self):
        pkt = create_config_network_transmit_set()
        return pkt

    def CONFIG_NETWORK_TRANSMIT_STATUS(self):
        pkt = create_config_network_transmit_status()
        return pkt

    def SEGMENT_ACK(self):
        pkt = create_segment_ack()
        return pkt

    def GENERIC_ONOFF_GET(self):
        pkt = create_generic_onoff_get()
        return pkt


class Ble_Mesh_Message_Handler():
    def __init__(self, advertiser_address: str, mesh_decrypter: MeshDecrypter):
        self.mesh_decrypter = mesh_decrypter
        self.advertiser_address = advertiser_address
        # self.network_key = self.mesh_decrypter.get_netkeys()[0]
        # self.application_key = self.mesh_decrypter.get_appkeys()[0]
        # self.device_key = self.mesh_decrypter.get_devkeys()[0]
        self.seq = 0
        self.packet_handle = Packet_Handle()

        self.received_message_list = []
    

    def receive_message_handler(self, pkt: Packet):
        # 从 BLEMesh_Message 层提取原始字节数据
        if pkt.haslayer('BLEMesh_Message'):
            mesh_layer = pkt.getlayer('BLEMesh_Message')
            # 将 BLEMesh_Message 层及其后续数据转换为 bytes
            pkt_bytes = raw(mesh_layer)
        else:
            pkt_bytes = raw(pkt)
        # result,segment_count , 第一个分段数据包的seqzero
        result, segment_count, seqzero = self.mesh_decrypter.decrypt(pkt_bytes)
        if result is not None and result != pkt_bytes:
            re_pkt = Message_Decode(result)
            print(f"receive_result_hex: {result.hex()}")
            self.seq += segment_count
            if seqzero not in self.received_message_list:
                # 记录 (SeqZero, 分段数量) 方便后续组装 SegmentAck
                self.received_message_list.append((seqzero, segment_count))
            return re_pkt
        else:
            return None

    def send_message_handler(self, packet_name, pkt: Packet, field_name: list = None, field_value: list = None, handle_mode: str = "None"):

        pkt = self.restore_packet(pkt, field_name, field_value)

        if packet_name == "config_composition_data_get_pkt":
            pkt_list = []
            self._set_message_headers(pkt)
            self.seq += 1
            pkt = self.restore_packet(pkt, field_name, field_value)
            raw_pkt = raw(pkt)  # 去掉最后的4个字节（MIC）
            print("config_composition_data_get_pkt unencrypted pkt:", raw(pkt).hex())
            encrypted_pkt = self.mesh_decrypter.encrypt(raw_pkt)               
            for pdu in encrypted_pkt:
                encrypted_pdu = EncryptedNetworkPDU(pdu)
                return_pkt = BTLE() / BTLE_ADV() / BTLE_ADV_NONCONN_IND(AdvA=self.advertiser_address) / EIR_Hdr(
                    type=0x2a) / encrypted_pdu
                pkt_list.append(return_pkt)
            return pkt_list

        elif packet_name == "config_app_key_add_pkt":
            pkt_list = []
            self._set_message_headers(pkt, seg=1)
            self.seq += 1
            pkt.app_key = self.mesh_decrypter.appkeys[0].key
            # self.application_key.key = os.urandom(16)
            print("config_app_key_add_pkt unencrypted pkt:", raw(pkt).hex())
            pkt = self.restore_packet(pkt, field_name, field_value)
            if handle_mode != "None":
                raw_pkt = self.packet_handle.handle_bytes(handle_mode,raw(pkt),os.random(len(raw(pkt))-6))
            else:
                raw_pkt = raw(pkt)
            encrypted_pkt = self.mesh_decrypter.encrypt(raw_pkt)
            for pdu in encrypted_pkt:
                encrypted_pdu = EncryptedNetworkPDU(pdu)
                return_pkt = BTLE() / BTLE_ADV() / BTLE_ADV_NONCONN_IND(AdvA=self.advertiser_address) / EIR_Hdr(
                    type=0x2a) / encrypted_pdu
                pkt_list.append(return_pkt)
            return pkt_list

        elif packet_name == "config_node_reset_pkt":
            pkt_list = []
            self._set_message_headers(pkt)
            self.seq += 1
            # print("unencrypted pkt:")
            # pkt.show2()
            hexdump(pkt)
            print("config_node_reset_pkt unencrypted pkt:", raw(pkt).hex())

            encrypted_pkt = self.mesh_decrypter.encrypt(raw(pkt))
            for pdu in encrypted_pkt:
                encrypted_pdu = EncryptedNetworkPDU(pdu)
                print("encrypted pdu:")
                encrypted_pdu.show2()
                hexdump(encrypted_pdu)
                return_pkt = BTLE() / BTLE_ADV() / BTLE_ADV_NONCONN_IND(AdvA=self.advertiser_address) / EIR_Hdr(
                    type=0x2a) / encrypted_pdu
                pkt_list.append(return_pkt)
            return pkt_list
        elif packet_name == "config_netkey_delete_pkt":
            pkt_list = []
            self._set_message_headers(pkt)
            self.seq += 1
            print("config_netkey_delete_pkt unencrypted pkt:", raw(pkt).hex())
            # pkt[ConfigNetKeyDelete].net_key_index = 0x0023
            pkt = self.restore_packet(pkt, field_name, field_value)
            encrypted_pkt = self.mesh_decrypter.encrypt(raw(pkt))
            for pdu in encrypted_pkt:
                encrypted_pdu = EncryptedNetworkPDU(pdu)
                return_pkt = BTLE() / BTLE_ADV() / BTLE_ADV_NONCONN_IND(AdvA=self.advertiser_address) / EIR_Hdr(
                    type=0x2a) / encrypted_pdu
                pkt_list.append(return_pkt)
            return pkt_list

        elif packet_name == 'config_netkey_add_pkt':
            pkt_list = []
            self._set_message_headers(pkt, seg=1)
            print("config_netkey_add_pkt unencrypted pkt:", raw(pkt).hex())
            pkt = self.restore_packet(pkt, field_name, field_value)
            encrypted_pkt = self.mesh_decrypter.encrypt(raw(pkt))
            for pdu in encrypted_pkt:
                self.seq += 1
                encrypted_pdu = EncryptedNetworkPDU(pdu)
                return_pkt = BTLE() / BTLE_ADV() / BTLE_ADV_NONCONN_IND(AdvA=self.advertiser_address) / EIR_Hdr(
                    type=0x2a) / encrypted_pdu
                pkt_list.append(return_pkt)
            return pkt_list

        elif packet_name == "config_model_app_bind_pkt":
            pkt_list = []
            self._set_message_headers(pkt)
            self.seq += 1
            print("config_model_app_bind_pkt unencrypted pkt:", raw(pkt).hex())
            pkt = self.restore_packet(pkt, field_name, field_value)
            encrypted_pkt = self.mesh_decrypter.encrypt(raw(pkt))
            for pdu in encrypted_pkt:
                encrypted_pdu = EncryptedNetworkPDU(pdu)
                return_pkt = BTLE() / BTLE_ADV() / BTLE_ADV_NONCONN_IND(AdvA=self.advertiser_address) / EIR_Hdr(
                    type=0x2a) / encrypted_pdu
                pkt_list.append(return_pkt)
            return pkt_list
        elif packet_name == "segment_ack_pkt":
            pkt_list = []
            pkt[Message_Decode].NID = self.mesh_decrypter.netkeys[0].nid
            pkt[Message_Decode].CTL = 1
            pkt[Message_Decode].TTL = 3
            pkt[Message_Decode].SEQ = self.seq
            pkt[Message_Decode].SRC = 0x0001
            pkt[Message_Decode].DST = 0x0005
            pkt[Message_Decode].IVI = 0x00
            seqzero, segment_count = self.received_message_list[0]
            pkt[SegmentAckPayload].SeqZero = seqzero
            # BlockAck 置位 0..segment_count 共 segment_count+1 个分段
            pkt[SegmentAckPayload].BlockAck = (1 << segment_count )
            self.received_message_list.pop(0)
            # self.seq += 1
            print("segment_ack_pkt unencrypted pkt:", raw(pkt).hex())
            pkt = self.restore_packet(pkt, field_name, field_value)
            encrypted_pkt = self.mesh_decrypter.encrypt(raw(pkt))
            for pdu in encrypted_pkt:
                encrypted_pdu = EncryptedNetworkPDU(pdu)
                return_pkt = BTLE() / BTLE_ADV() / BTLE_ADV_NONCONN_IND(AdvA=self.advertiser_address) / EIR_Hdr(
                    type=0x2a) / encrypted_pdu
                pkt_list.append(return_pkt)
            return pkt_list

        elif packet_name == "config_netkey_update_pkt":
            pkt_list = []
            if pkt.haslayer(Seg_Access_Message):
                seg = 1
            else:
                seg = 0
            pkt.getlayer(ConfigNetworkKeyUpdate).net_key = os.urandom(16)
            print("netkey:", pkt.getlayer(ConfigNetworkKeyUpdate).net_key.hex())
            #从新记录netkey 
            # self.mesh_decrypter.netkeys[0].netkey_set(pkt.getlayer(ConfigNetworkKeyUpdate).net_key)
            #修改写入到json文件
            # with open(key_path, 'w') as f:
            #     json.dump(data, f, indent=4)
            self._set_message_headers(pkt, seg=seg)
            self.seq += 1
            print("unencrypted pkt:", raw(pkt).hex())
            pkt = self.restore_packet(pkt, field_name, field_value)
            encrypted_pkt = self.mesh_decrypter.encrypt(raw(pkt))
            for pdu in encrypted_pkt:
                encrypted_pdu = EncryptedNetworkPDU(pdu)
                print("encrypted pdu:")
                encrypted_pdu.show2()
                hexdump(encrypted_pdu)
                return_pkt = BTLE() / BTLE_ADV() / BTLE_ADV_NONCONN_IND(AdvA=self.advertiser_address) / EIR_Hdr(
                    type=0x2a) / encrypted_pdu
                pkt_list.append(return_pkt)
            return pkt_list

        elif packet_name == "config_key_refresh_phase_set_pkt":
            pkt_list = []
            self._set_message_headers(pkt)
            self.seq += 1
            # self.mesh_decrypter.netkeys[0].netkey_set(pkt.getlayer(ConfigNetworkKeyUpdate).net_key)
            print("config_key_refresh_phase_set_pkt unencrypted pkt:", raw(pkt).hex())
            pkt = self.restore_packet(pkt, field_name, field_value)
            encrypted_pkt = self.mesh_decrypter.encrypt(raw(pkt))
            for pdu in encrypted_pkt:
                encrypted_pdu = EncryptedNetworkPDU(pdu)
                return_pkt = BTLE() / BTLE_ADV() / BTLE_ADV_NONCONN_IND(AdvA=self.advertiser_address) / EIR_Hdr(
                    type=0x2a) / encrypted_pdu
                pkt_list.append(return_pkt)
            return pkt_list
        else:
            pkt_list = []
            if pkt.haslayer(Seg_Access_Message):
                seg = 1
            else:
                seg = 0
            self._set_message_headers(pkt, seg=seg)
            self.seq += 1
            # print("----------------------------------------------")
            # tx_summary = "TX ---> " + " | ".join(pkt.summary().split(" / "))
            # print(tx_summary)
            # print("----------------------------------------------")
            # pkt.show2()
            # print("----------------------------------------------")
            # pkt = pkt/Raw(os.urandom(7))  # 添加随机数据以增加包的长度
            # print(f"seq: {pkt.seq}")
            print("unencrypted pkt:", raw(pkt).hex())
            pkt = self.restore_packet(pkt, field_name, field_value)
            encrypted_pkt = self.mesh_decrypter.encrypt(raw(pkt))
            for pdu in encrypted_pkt:
                encrypted_pdu = EncryptedNetworkPDU(pdu)
                print("encrypted pdu:")
                encrypted_pdu.show2()
                hexdump(encrypted_pdu)
                return_pkt = BTLE() / BTLE_ADV() / BTLE_ADV_NONCONN_IND(AdvA=self.advertiser_address) / EIR_Hdr(
                    type=0x2a) / encrypted_pdu
                pkt_list.append(return_pkt)
            return pkt_list

        return pkt

    def _set_message_headers(self, pkt: Packet, ctl=0, ttl=3, seg=0, akf=None, aid=None, dst=None):
        network_layer = pkt.getlayer(Message_Decode)

        # print(f"seq: {self.seq}")
        if network_layer:
            network_layer.NID = self.mesh_decrypter.netkeys[0].nid
            network_layer.CTL = ctl
            network_layer.TTL = ttl
            network_layer.SEQ = self.seq
            network_layer.SRC = 0x0001
            network_layer.DST = dst if dst is not None else self.mesh_decrypter.devkeys[0].address
            network_layer.IVI = self.mesh_decrypter.netkeys[0].iv_index & 0x01
        transport_layer = (
            pkt.getlayer(Unseg_Access_Message)
            or pkt.getlayer(Seg_Access_Message)
            or pkt.getlayer(Control_Message)
            or pkt.getlayer(Unseg_Control_Message)
            or pkt.getlayer(Seg_Control_Message)
        )
        if transport_layer:
            if hasattr(transport_layer, "SEG"):
                transport_layer.SEG = seg
            if hasattr(transport_layer, "AKF"):
                if akf is not None:
                    transport_layer.AKF = akf
                # transport_layer.AKF = akf
                if transport_layer.AKF == 1:
                    if hasattr(transport_layer, "AID"):
                        transport_layer.AID =self.mesh_decrypter.appkeys[0].aid
                    else:
                        print("Error: AID is not in pkt")

    def restore_packet(self, pkt: Packet, field_name: list = None, field_value: list = None):
        # 先判断pkt中是否存在field_name,如果存在，则设置field_value
        # 判断 两个list的长度是否相等
        if field_name is not None and field_value is not None:
            for i in range(len(field_name)):
                # 递归查找字段
                if not self._set_field_recursive(pkt, field_name[i], field_value[i]):
                    # pkt.show2()
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


