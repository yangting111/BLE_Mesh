# Copyright (c) 2016, Nordic Semiconductor
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of ble_mesh_decrypter nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
import struct

# 支持直接运行和作为模块导入
try:
    from .kdf import KDF
except ImportError:
    from kdf import KDF


class NetworkKey(object):
    def __init__(self, key, iv_index):
        self.key = key
        out = KDF().k2(key, b'\x00')
        self.nid = out[15] & 0x7F         
        self.encryption_key = out[16:32]  
        self.privacy_key = out[32:48]     
        self.NetworkID = KDF().k3(key)
        self.iv_index = iv_index

        # 补充 BeaconKey - 用于Secure Network Beacon
        beacon_salt = KDF().s1(b"nkbk")  # "nkbk" = network key beacon key
        beacon_p = b"id128" + b"\x01"
        self.BeaconKey = KDF().k1(key, beacon_salt, beacon_p)

        # 补充 PrivateBeaconKey - 用于Private Beacon
        private_beacon_salt = KDF().s1(b"nkpk")  # "nkpk" = network key private key
        private_beacon_p = b"id128" + b"\x01"
        self.PrivateBeaconKey = KDF().k1(key, private_beacon_salt, private_beacon_p)
    def beacon_key_get(self):
        return self.BeaconKey
    
    def auth_value_get(self, flags, network_id, iv_index):
        """计算 Secure Network Beacon 的 Authentication Value
        Authentication Value = AES-CMAC(BeaconKey)(Flags || Network ID || IV Index)[0-7]
        Args:
            flags: 1 byte Flags 字段
            network_id: 8 bytes Network ID
            iv_index: 4 bytes IV Index (int 或 bytes)
        Returns:
            8 bytes Authentication Value
        """
        from Crypto.Hash import CMAC
        from Crypto.Cipher import AES
        import struct
        
        # 处理 flags
        if isinstance(flags, int):
            flags = struct.pack(">B", flags)
        
        # 处理 iv_index
        if isinstance(iv_index, int):
            iv_index = struct.pack(">I", iv_index)
        
        # 构建输入: Flags (1 byte) || Network ID (8 bytes) || IV Index (4 bytes)
        data = flags + network_id + iv_index
        
        # AES-CMAC with BeaconKey
        cmac = CMAC.new(self.BeaconKey, ciphermod=AES)
        cmac.update(data)
        
        # 返回前 8 字节
        return cmac.digest()[0:8]

    def netkey_set(self, key):
        self.key = key
        out = KDF().k2(key, b'\x00')
        # k2 output structure: T1 (16 bytes) || T2 (16 bytes) || T3 (16 bytes)
        # According to spec: NID || EncryptionKey || PrivacyKey = k2(NetKey, 0x00)
        # But k2 returns: T1 || T2 || T3
        # Correct extraction:
        # - NID = T1[15] & 0x7F (last byte of T1, 7 bits)
        # - EncryptionKey = T2 (16 bytes)
        # - PrivacyKey = T3 (16 bytes)
        self.nid = out[15] & 0x7F         # NID from last 7 bits of T1
        self.encryption_key = out[16:32]  # T2 = EncryptionKey
        self.privacy_key = out[32:48]     # T3 = PrivacyKey
        self.NetworkID = KDF().k3(key)

    def netkey_get(self):
        return self.key

    def iv_index_set(self, iv_index):
        self.iv_index = iv_index

    def iv_index_get(self, pdu):
        """Gets the IV index used for decryption based on the IVI bit"""
        # Check the IVI bit to see if we're using the current or previous IV index.
        if (self.iv_index & 0x01) != (pdu[0] >> 7):
            # Use previous IV Index, but ensure it doesn't go below 0
            iv_index = max(0, self.iv_index - 1)
        else:
            iv_index = self.iv_index
        return iv_index

    def deobfuscate(self, pdu):
        """Attempts to deobfuscate the network PDU header (CTL, TTL, SEQ, SRC)"""
        iv_index = self.iv_index_get(pdu)
        privacy_random = pdu[7:(7 + 7)]
        pecb_input = (bytes(5)
                      + struct.pack(">I", iv_index)
                      + privacy_random)
        pecb = AES.new(self.privacy_key, mode=AES.MODE_ECB).encrypt(pecb_input)
        return bytes([pdu[0]]) + strxor(pdu[1:7], pecb[0:6]) + pdu[7:]

    def obfuscate(self, pdu, enc_pdu):
        """Attempts to enobfuscate the network PDU header (CTL, TTL, SEQ, SRC)"""
        """pdu : CTL, TTL, SEQ, SRC"""
        """enc_pdu : (EncDST || EncTransportPDU || NetMIC)"""
        if len(enc_pdu) < 7:
            raise ValueError(f"enc_pdu too short for obfuscation: {len(enc_pdu)} bytes, need at least 7. "
                           f"Check if TransportPDU encryption succeeded.")
        iv_index = self.iv_index
        privacy_random = enc_pdu[0:7]
        pecb_input = (bytes(5)
                      + struct.pack(">I", iv_index)
                      + privacy_random)
        pecb = AES.new(self.privacy_key, mode=AES.MODE_ECB).encrypt(pecb_input)
        return strxor(pdu, pecb[0:6])

    def decrypt(self, pdu):
        iv_index = self.iv_index_get(pdu)
        # Ref. Mesh Profile spec v1.0 table 3.45
        # Exploit the PDU layout according to table 3.7
        nonce = (bytes(1)
                 + pdu[1:(1 + 1 + 3 + 2)]
                 + bytes(2)
                 + struct.pack(">I", iv_index))
        if (pdu[1] & 0x80) > 0:
            mac_len = 8
        else:
            mac_len = 4

        MIN_NETWORK_LEN = 10
        if (len(pdu) - MIN_NETWORK_LEN - mac_len) < 0:
            # print("Length of the PDU is too small: ", len(pdu))
            return None

        ciphertext = pdu[7:-mac_len]
        mac = pdu[-mac_len:]
        self.ccm = AES.new(self.encryption_key, mode=AES.MODE_CCM,
                           nonce=nonce,
                           mac_len=mac_len,
                           msg_len=len(ciphertext),
                           assoc_len=0)
        try:
            cleartext = self.ccm.decrypt_and_verify(ciphertext, mac)
            return pdu[0:7] + cleartext + mac
        except ValueError as e:
            # MAC check failed
            # print("MAC check failed: ", mac.hex())
            return None

    def encrypt(self, iv_index, pdu):
        """Encrypts the given PDU(IVI, NID, CTL, TTL, SEQ, SRC, DST, TransportPDU, TransMIC)"""
        if self.iv_index != iv_index:
            self.iv_index_set(iv_index)
        nonce = (bytes(1)
                 + pdu[1:(1 + 1 + 3 + 2)]
                 + bytes(2)
                 + struct.pack(">I", iv_index))
        # print(f"NetworkKey encrypt nonce: {nonce.hex()}")
        # print(f"NetworkKey encrypt input PDU: {pdu.hex()}")
        if (pdu[1] & 0x80) > 0:
            mac_len = 8
        else:
            mac_len = 4
        ciphertext = pdu[7:]  # 只加密DST+TransportPDU部分

        # print(f"NetworkKey encrypt ciphertext: {ciphertext.hex()}")
        # print(f"NetworkKey encrypt nonce: {nonce.hex()}")
        # print(f"NetworkKey encrypt key: {self.encryption_key.hex()}")
        # print(f"NetworkKey network key: {self.key.hex()}")
        # print(f"seq: {pdu[2:5].hex()}")

        self.ccm = AES.new(self.encryption_key, mode=AES.MODE_CCM, nonce=nonce,
                           mac_len=mac_len,
                           msg_len=len(ciphertext),
                           assoc_len=0)
        try:
            encrytext, mac = self.ccm.encrypt_and_digest(ciphertext)
            return pdu[0:7], encrytext + mac
        except ValueError as e:
            return None


class ApplicationKey(object):
    def __init__(self, key):
        """初始化ApplicationKey
        Args:
            key: 16字节的应用密钥
        """
        if isinstance(key, str):
            key = bytes.fromhex(key)
        elif isinstance(key, bytearray):
            key = bytes(key)

        if not isinstance(key, bytes) or len(key) != 16:
            raise ValueError("ApplicationKey必须是16字节")

        self.key = key
        self.aid = KDF().k4(self.key)

    def decrypt(self, szmic_hint, seqzero_hint, seq: bytes, src: bytes, dst: bytes, iv_index: int, pdu: bytes):
        """解密使用ApplicationKey加密的Access PDU

        Args:
            szmic_hint: MIC大小标志提示 (0=32bit, 1=64bit)，用于重组后的非分段消息
            seqzero_hint: SeqZero提示，用于重组后的消息重构SEQ
            seq: 3字节序列号
            src: 2字节源地址
            dst: 2字节目标地址
            iv_index: IV Index值
            pdu: 完整的PDU（包含网络层头部）

        Returns:
            解密后的Access PDU，如果解密失败返回None
        """
        # 参数验证
        seg = (pdu[9] & 0b10000000) >> 7
        akf = (pdu[9] & 0b01000000) >> 6
        aid = pdu[9] & 0b00111111
        aszmic = 0
        mac_len = 4
        access_payload = pdu[10:-4]
        trans_mic = pdu[-4:]

        seq_int = int.from_bytes(seq, 'big')
        src_int = int.from_bytes(src, 'big')
        dst_int = int.from_bytes(dst, 'big')

        if seg != 0:
            bytes_10_13 = int.from_bytes(pdu[10:13], 'big')
            szmic = (bytes_10_13 & 0x800000) >> 23
            seqzero = (bytes_10_13 & 0x7ffc00) >> 10
            sego = (bytes_10_13 & 0x0003e0) >> 5
            segn = (bytes_10_13 & 0x00001f)
            aszmic = szmic
            if szmic == 1:
                mac_len = 8
                access_payload = pdu[13:-8]
                trans_mic = pdu[-8:]
            else:
                mac_len = 4
                access_payload = pdu[13:-4]
                trans_mic = pdu[-4:]
            # 重构完整的序列号：保留seq的高位，用seqzero替换低13位
            seq = struct.pack(">I", ((seq_int & 0xFFE000) | seqzero))[0:3]
        else:
            # 对于非分段消息或重组后的消息，使用szmic_hint
            aszmic = szmic_hint
            if szmic_hint == 1:
                mac_len = 8
                access_payload = pdu[10:-8]
                trans_mic = pdu[-8:]
            else:
                mac_len = 4
                access_payload = pdu[10:-4]
                trans_mic = pdu[-4:]
            # 对于重组后的消息，使用seqzero_hint重构SEQ
            if seqzero_hint is not None:
                seq = struct.pack(">I", ((seq_int & 0xFFE000) | seqzero_hint))[0:3]
        # 确定MAC长度

        nonce = (b'\x01'
                 + struct.pack(">B", (aszmic << 7) | 0x00)  # ASZMIC (1 bit) + Pad (7 bits, 0b0000000)
                 + seq
                 + struct.pack(">H", src_int)
                 + struct.pack(">H", dst_int)
                 + struct.pack(">I", iv_index)
                 )

        # print(f"ApplicationKey decrypt nonce: {nonce.hex()}")
        # print(f"ApplicationKey decrypt access_payload: {access_payload.hex()}")
        # print(f"ApplicationKey decrypt trans_mic: {trans_mic.hex()}")
        # print(f"ApplicationKey decrypt mac_len: {mac_len}")
        # 使用CCM模式加密
        ccm = AES.new(self.key, mode=AES.MODE_CCM, nonce=nonce, mac_len=mac_len)
        try:
            plaintext = ccm.decrypt_and_verify(access_payload, trans_mic)
            # print(f"ApplicationKey decrypt plaintext: {plaintext.hex()}")
            return plaintext
        except ValueError as e:
            # print("ApplicationKey decrypt failed: ", str(e))
            return None

    def encrypt(self, seq: bytes, src: bytes, dst: bytes, iv_index: int, pdu: bytes,seq_zero: bytes = None):
        """使用ApplicationKey加密Access PDU
        Args:
            szmic: MIC大小标志 (0=32bit, 1=64bit)
            seq: 3字节序列号
            src: 2字节源地址
            dst: 2字节目标地址
            iv_index: IV Index值
            access_pdu: 要加密的Access PDU

        Returns:
            加密后的数据(ciphertext + TransMIC)，如果加密失败返回None
        """
        # 参数验证
        seg = (pdu[9] & 0b10000000) >> 7
        akf = (pdu[9] & 0b01000000) >> 6
        aid = pdu[9] & 0b00111111
        aszmic = 0
        access_payload = pdu[10:]

        seq_int = int.from_bytes(seq, 'big')
        src_int = int.from_bytes(src, 'big')
        dst_int = int.from_bytes(dst, 'big')

        if seg != 0:
            bytes_10_13 = int.from_bytes(pdu[10:13], 'big')
            szmic = (bytes_10_13 & 0x800000) >> 23

            aszmic = szmic
            access_payload = pdu[13:]
            seq = struct.pack(">I", ((seq_int & 0xFFE000) | seq_zero))[1:4]
        # 确定MAC长度

        if seg != 0 and szmic == 1:
            mac_len = 8  # 64-bit TransMIC
        else:
            mac_len = 4  # 32-bit TransMIC

        nonce = (b'\x01'
                 + struct.pack(">B", (aszmic << 7) | 0x00)  # ASZMIC (1 bit) + Pad (7 bits, 0b0000000)
                 + seq
                 + struct.pack(">H", src_int)
                 + struct.pack(">H", dst_int)
                 + struct.pack(">I", iv_index)
                 )

        print(f"ApplicationKey encrypt nonce: {nonce.hex()}")
        # print(f"ApplicationKey encrypt input PDU: {access_payload.hex()}")
        # print(f"ApplicationKey encrypt mac_len: {mac_len}")
        # 使用CCM模式加密
        ccm = AES.new(self.key, mode=AES.MODE_CCM, nonce=nonce, mac_len=mac_len)
        try:
            ciphertext, trans_mic = ccm.encrypt_and_digest(access_payload)
            # print(f"ApplicationKey encrypt ciphertext: {ciphertext.hex()}")
            # print(f"ApplicationKey encrypt trans_mic: {trans_mic.hex()}")
            return ciphertext + trans_mic
        except ValueError as e:
            # print("ApplicationKey encrypt failed: ", str(e))
            return None


class DeviceKey(object):

    def __init__(self, key, address):
        self.key = key
        self.address = address

    def decrypt(self, szmic, seq: bytes, src: bytes, dst: bytes, iv_index: int, pdu: bytes):

        seg = (pdu[9] & 0b10000000) >> 7
        akf = (pdu[9] & 0b01000000) >> 6
        aid = pdu[9] & 0b00111111
        aszmic = 0
        mac_len = 4
        access_payload = pdu[10:-4]
        trans_mic = pdu[-4:]

        seq_int = int.from_bytes(seq, 'big')
        src_int = int.from_bytes(src, 'big')
        dst_int = int.from_bytes(dst, 'big')

        if seg != 0:
            bytes_10_13 = int.from_bytes(pdu[10:13], 'big')
            szmic = (bytes_10_13 & 0x800000) >> 23
            seqzero = (bytes_10_13 & 0x7ffc00) >> 10
            sego = (bytes_10_13 & 0x0003e0) >> 5
            segn = (bytes_10_13 & 0x00001f)
            aszmic = szmic
            if szmic == 1:
                mac_len = 8
                access_payload = pdu[13:-8]
                trans_mic = pdu[-8:]
            else:
                mac_len = 4
                access_payload = pdu[13:-4]
                trans_mic = pdu[-4:]
            # 重构完整的序列号：保留seq的高位，用seqzero替换低13位
            seq = struct.pack(">I", ((seq_int & 0xFFE000) | seqzero))[0:3]
        # 确定MAC长度

        nonce = (b'\x02'
                 + struct.pack(">B", (aszmic << 7) | 0x00)  # ASZMIC (1 bit) + Pad (7 bits, 0b0000000)
                 + seq
                 + struct.pack(">H", src_int)
                 + struct.pack(">H", dst_int)
                 + struct.pack(">I", iv_index)
                 )

        # print(f"DeviceKey decrypt input PDU: {access_payload.hex()}")
        # print(f"DeviceKey decrypt trans_mic: {trans_mic.hex()}")
        # print(f"DeviceKey decrypt nonce: {nonce.hex()}")
        # 使用CCM模式加密
        ccm = AES.new(self.key, mode=AES.MODE_CCM, nonce=nonce, mac_len=mac_len)
        try:
            plaintext = ccm.decrypt_and_verify(access_payload, trans_mic)
            # print(f"DeviceKey decrypt plaintext: {plaintext.hex()}")
            return plaintext
        except ValueError as e:
            # print("DeviceKey decrypt failed: ", str(e))
            return None

    def encrypt(self, seq: bytes, src: bytes, dst: bytes, iv_index: int, pdu, seq_zero: bytes = None):
        """Encrypts the given PDU using DeviceKey"""
        # 参数验证
        seg = (pdu[9] & 0b10000000) >> 7
        akf = (pdu[9] & 0b01000000) >> 6
        aid = pdu[9] & 0b00111111
        aszmic = 0
        access_payload = pdu[10:]

        seq_int = int.from_bytes(seq, 'big')
        src_int = int.from_bytes(src, 'big')
        dst_int = int.from_bytes(dst, 'big')

        if seg != 0:
            bytes_10_13 = int.from_bytes(pdu[10:13], 'big')
            szmic = (bytes_10_13 & 0x800000) >> 23
            # 如果没有传入seq_zero，则从PDU中提取
            # sego = (bytes_10_13 & 0x0003e0) >> 5
            # segn = (bytes_10_13 & 0x00001f)
            aszmic = szmic
            access_payload = pdu[13:]
            seq = struct.pack(">I", ((seq_int & 0xFFE000) | seq_zero))[1:4]
            print(f"seq_int: {seq_int}, seq_zero: {seq_zero}, seq: {seq.hex()}")
        # 确定MAC长度
        if seg != 0 and szmic == 1:
            mac_len = 8  # 64-bit TransMIC
        else:
            mac_len = 4  # 32-bit TransMIC

        nonce = (b'\x02'
                 + struct.pack(">B", (aszmic << 7) | 0x00)  # ASZMIC (1 bit) + Pad (7 bits, 0b0000000)
                 + seq
                 + struct.pack(">H", src_int)
                 + struct.pack(">H", dst_int)
                 + struct.pack(">I", iv_index)
                 )
        print(f"DeviceKey encrypt nonce: {nonce.hex()}")
        print(f"DeviceKey encrypt access_payload: {access_payload.hex()}")
        print(f"DeviceKey encrypt key: {self.key.hex()}")

        ccm = AES.new(self.key, mode=AES.MODE_CCM, nonce=nonce, mac_len=mac_len)
        try:
            encrytext, mac = ccm.encrypt_and_digest(access_payload)
            # print(f"DeviceKey encrypt encrytext and mac: {(encrytext + mac).hex()}")
            return encrytext + mac
        except ValueError as e:
            return None


if __name__ == "__main__":
    # test secure network beacon authentication value
    # 测试数据来自 Bluetooth Mesh 规范
    # NetKey: 7dd7364cd842ad18c17c2b820c84c3d6
    # IV Index: 12345679 (0x00BC614F)
    # Flags: 00
    # Network ID: 3ecaff672f673370
    # BeaconKey: 5423d967da639a99cb02231a83f7d254
    # Expected Authentication Value: c62f09e4c957f59d
    
    from Crypto.Hash import CMAC
    from Crypto.Cipher import AES
    import struct
    
    netkey = bytes.fromhex("7dd7364cd842ad18c17c2b820c84c3d6")
    iv_index = 0x12345679
    flags = 0x00
    network_id = bytes.fromhex("3ecaff672f673370")
    expected_beacon_key = bytes.fromhex("5423d967da639a99cb02231a83f7d254")
    expected_auth_value = bytes.fromhex("c62f09e4c957f59d")
    
    # 创建 NetworkKey 对象
    nk = NetworkKey(netkey, iv_index)
    
    print(f"NetKey: {netkey.hex()}")
    print(f"BeaconKey: {nk.BeaconKey.hex()}")
    print(f"Expected BeaconKey: {expected_beacon_key.hex()}")
    print(f"BeaconKey Match: {nk.BeaconKey == expected_beacon_key}")
    print()
    print(f"Network ID: {nk.NetworkID.hex()}")
    print(f"Expected Network ID: {network_id.hex()}")
    print(f"Network ID Match: {nk.NetworkID == network_id}")
    print()
    
    # 计算 Authentication Value
    auth_value = nk.auth_value_get(flags, network_id, iv_index)
    print(f"Calculated Auth Value: {auth_value.hex()}")
    print(f"Expected Auth Value: {expected_auth_value.hex()}")
    print(f"Auth Value Match: {auth_value == expected_auth_value}")