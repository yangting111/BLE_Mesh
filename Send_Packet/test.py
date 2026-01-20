import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/libs/")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/libs/boofuzz/")

# print(sys.path)

from Transfer.Send_Packet.Ble_Mesh_PBADV import Ble_Mesh_PBADV

ble_mesh_pbadv = Ble_Mesh_PBADV(link_id=1, advertiser_address="00:a0:50:00:00:1d")

pkt = ble_mesh_pbadv.LINK_OPEN_MESSAGE()
pkt.show()