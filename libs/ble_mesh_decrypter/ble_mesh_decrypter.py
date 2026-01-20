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

from curses import raw
import sys
import os

# Add the current directory to the Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

# Add parent libs directory to path for scapy imports
libs_dir = os.path.dirname(current_dir)
if libs_dir not in sys.path:
    sys.path.insert(0, libs_dir)

try:
    from .utils import key
except ImportError:
    from utils import key

import struct
import math


class UpperTransportSegmenter(object):
    """Upper Transport PDU分段器

    根据BLE Mesh规范实现Upper Transport Access PDU的分段功能
    """

    # 段大小常量
    ACCESS_SEGMENT_SIZE = 12  # Upper Transport Access PDU每段12字节
    CONTROL_SEGMENT_SIZE = 8  # Upper Transport Control PDU每段8字节

    def __init__(self, iv_index):
        """初始化分段器

        Args:
            iv_index: 当前的IV Index值
        """
        self.iv_index = iv_index

    def calculate_seq_auth(self, seq, iv_index=None):

        """
        计算seq_auth值

        Args:
            iv_index (int, optional): 指定IV索引，如果为None则使用当前值
            seq (int, optional): 指定序列号，如果为None则使用当前值

        Returns:
            int: 56位的seq_auth值
        """
        current_iv = iv_index
        current_seq = seq

        # 处理seq参数类型转换
        if isinstance(current_seq, bytes):
            if len(current_seq) != 3:
                raise ValueError("序列号bytes必须是3字节")
            current_seq = int.from_bytes(current_seq, 'big')

        # 确保数值范围正确
        current_iv &= 0xFFFFFFFF  # 32位
        current_seq &= 0xFFFFFF  # 24位

        # seq_auth = (IV_Index << 24) | SEQ
        seq_auth = (current_iv << 24) | current_seq

        return seq_auth

    def calculate_seq_zero(self, seq_auth):
        """从SeqAuth计算SeqZero

        Args:
            seq_auth: SeqAuth值 (int类型或7字节的bytes)

        Returns:
            13位的SeqZero值
        """
        # 处理seq_auth参数类型
        if isinstance(seq_auth, bytes):
            seq_auth_int = int.from_bytes(seq_auth, 'big')
        else:
            seq_auth_int = seq_auth

        # SeqZero是SeqAuth的最低13位
        seq_zero = seq_auth_int & 0x1FFF  # 取最低13位
        return seq_zero

    def segment_upper_transport_pdu(self, upper_transport_pdu, seq, szmic, is_control=False):
        """对Upper Transport PDU进行分段  对加密信息进行分段
        Args:
            upper_transport_pdu: 加密后的Upper Transport PDU
            seq: 第一个段的序列号
            is_control: 是否为控制PDU (False=Access PDU, True=Control PDU)

        Returns:
            list: 分段列表，每个元素包含 {
                'seg_o': 段序号,
                'seg_n': 总段数-1,
                'seq_zero': SeqZero值,
                'segment_data': 段数据,
                'seq': 该段的序列号
            }
        """
        if not isinstance(upper_transport_pdu, bytes):
            raise ValueError("Upper Transport PDU必须是bytes类型")

        # 检查长度限制
        if is_control:
            segment_size = self.CONTROL_SEGMENT_SIZE
            max_single_size = 11  # Control PDU超过11字节需要分段
        else:
            segment_size = self.ACCESS_SEGMENT_SIZE
            max_single_size = 15  # Access PDU超过15字节需要分段

        pdu_length = len(upper_transport_pdu)

        # 检查是否需要分段
        if pdu_length <= max_single_size:
            # 可以用单段传输，但这里仍然可以选择分段传输
            # 根据规范，单段也可以使用分段格式以获得确认
            pass

        # 计算需要的段数
        num_segments = math.ceil(pdu_length / segment_size)
        if num_segments > 32:
            raise ValueError(f"PDU过大，需要{num_segments}段，超过最大32段限制")

        # 计算SeqAuth和SeqZero
        seq_auth = self.calculate_seq_auth(seq, self.iv_index)
        seq_zero = self.calculate_seq_zero(seq_auth)

        segments = []
        current_seq = seq if isinstance(seq, int) else int.from_bytes(seq, 'big')

        for seg_o in range(num_segments):
            # 计算当前段的数据
            start_offset = seg_o * segment_size
            end_offset = min(start_offset + segment_size, pdu_length)
            segment_data = upper_transport_pdu[start_offset:end_offset]

            # 添加seq和seq_auth信息
            segment_info = {
                'szmic': szmic,
                'seq_zero': seq_zero,
                'seg_o': seg_o,
                'seg_n': num_segments - 1,
                'segment_data': segment_data,
                'seq': current_seq,
                'seq_auth': seq_auth,
            }
            seg_pdu = self.create_segmented_lower_transport_pdu(segment_info, szmic)
            segments.append(seg_pdu)
            print(f"segments_info: {segment_info}")
            current_seq = (current_seq + 1) & 0xFFFFFF  # 24位序列号递增
        return segments

    def create_segmented_lower_transport_pdu(self, segment_info, szmic=0):
        """创建分段的Lower Transport PDU

        Args:
            segment_info: 段信息字典
            szmic: MIC大小标志 (0=32bit, 1=64bit)

        Returns:
            bytes: 分段的Lower Transport PDU
        """
        seg_o = segment_info['seg_o']
        seg_n = segment_info['seg_n']
        seq_zero = segment_info['seq_zero']
        segment_data = segment_info['segment_data']

        # 验证参数范围
        if seg_o > 31:
            raise ValueError(f"SegO值{seg_o}超出范围(0-31)")
        if seg_n > 31:
            raise ValueError(f"SegN值{seg_n}超出范围(0-31)")
        if seq_zero > 0x1FFF:
            raise ValueError(f"SeqZero值{seq_zero}超出13位范围")

        # 根据BLE Mesh规范，分段Lower Transport PDU格式为3字节头部：
        # 字节0: SEG(1) + OpCode(7) = 10000000 (SEG=1表示分段消息)
        # 字节1-2: SZMIC(1) + SeqZero(13) + SegO(5) + SegN(5) = 24位

        # 第一个字节: SEG=1, OpCode=0 (Access消息的分段头部没有特定OpCode)
        byte0 = 0x80  # SEG=1

        # # 第二、三字节: SZMIC(1位) + SeqZero(13位) + SegO(5位) + SegN(5位) = 24位
        # print(f"szmic: {szmic}")
        # print(f"seq_zero: {seq_zero}")
        # print(f"seg_o: {seg_o}")
        # print(f"seg_n: {seg_n}")

        # 正确的3字节格式：SZMIC(1) + SeqZero(13) + SegO(5) + SegN(5)
        header_24bits = ((szmic & 0x1) << 23) | ((seq_zero & 0x1FFF) << 10) | ((seg_o & 0x1F) << 5) | (seg_n & 0x1F)

        # 分解为3字节
        byte1 = (header_24bits >> 16) & 0xFF
        byte2 = (header_24bits >> 8) & 0xFF
        byte3 = header_24bits & 0xFF

        # print(f"3字节头部: {byte0:02x} {byte1:02x} {byte2:02x} {byte3:02x}")
        # 组装完整的分段PDU

        segmented_pdu = bytes([byte0, byte1, byte2, byte3]) + segment_data
        # print(f"segmented_pdu: {segmented_pdu.hex()}")

        return segmented_pdu

    def format_segment_binary_representation(self, segment_info):
        """将segment信息格式化为二进制表示

        Args:
            segment_info: 段信息字典

        Returns:
            str: 二进制格式表示字符串
        """
        szmic = segment_info.get('szmic', 0)
        seq_zero = segment_info.get('seq_zero', 0)
        seg_o = segment_info.get('seg_o', 0)
        seg_n = segment_info.get('seg_n', 0)

        # 创建二进制表示
        lines = []

        # SZMIC字段 (1位) - 在最高位
        szmic_desc = f"SZMIC: {'64-bit' if szmic else '32-bit'} ({szmic})"
        lines.append(f"{szmic}... .... .... .... .... = {szmic_desc}")

        # SeqZero字段 (13位) - 接下来的13位，需要跨越多个字节
        seq_zero_bits = f"{seq_zero:013b}"
        # 将13位分解为: 3位在第一个字节, 8位在第二个字节, 2位在第三个字节
        lines.append(f".000 0000 0000 00.. .... = SeqZero: {seq_zero}")

        # SegO字段 (5位) - 接下来的5位
        seg_o_bits = f"{seg_o:05b}"
        lines.append(f".... .... .... ..00 000. .... = Segment Offset number(SegO): {seg_o}")

        # SegN字段 (5位) - 最后5位，跨越字节3和字节4
        seg_n_bits = f"{seg_n:05b}"
        seg_n_formatted = f"{seg_n:05b}"
        lines.append(f".... .... .... .... ...0 0001 = Last Segment number(SegN): {seg_n}")

        return "\n".join(lines)

    def create_segment_bytes_with_wireshark_format(self, segment_info):
        """按照Wireshark的组包顺序生成segment字节序列

        Args:
            segment_info: 段信息字典，包含szmic, seq_zero, seg_o, seg_n

        Returns:
            tuple: (bytes序列, 格式化的二进制表示字符串)
        """
        szmic = segment_info.get('szmic', 0)
        seq_zero = segment_info.get('seq_zero', 0)
        seg_o = segment_info.get('seg_o', 0)
        seg_n = segment_info.get('seg_n', 0)

        # 验证参数范围
        if seg_o > 31:
            raise ValueError(f"SegO值{seg_o}超出范围(0-31)")
        if seg_n > 31:
            raise ValueError(f"SegN值{seg_n}超出范围(0-31)")
        if seq_zero > 0x1FFF:
            raise ValueError(f"SeqZero值{seq_zero}超出13位范围")
        if szmic > 1:
            raise ValueError(f"SZMIC值{szmic}超出1位范围")

        # 按照BLE Mesh规范构建分段头部字节
        # 字节0: SEG(1) + OpCode(7) = 10000000 (SEG=1表示分段消息)
        byte0 = 0x80  # SEG=1, OpCode=0

        # 字节1-2: SZMIC(1位) + SeqZero(13位) + SegO(5位) = 19位总共
        # 需要分配到2个字节中：字节1(8位) + 字节2(8位) + 字节3的前3位
        szmic_seqzero_sego = (szmic << 18) | (seq_zero << 5) | seg_o
        byte1 = (szmic_seqzero_sego >> 8) & 0xFF
        byte2 = szmic_seqzero_sego & 0xFF

        # 字节3: SegN(5位) + RFU(3位)
        byte3 = (seg_n << 3) & 0xF8  # RFU字段置0

        # 组装4字节头部
        header_bytes = bytes([byte0, byte1, byte2, byte3])

        # 创建Wireshark风格的二进制表示
        lines = []

        # 分析每个字节的位域
        # 字节0: 1000 0000 (SEG=1, OpCode=0000000)
        lines.append(f"字节0: {byte0:02x} = {byte0:08b}")
        lines.append(f"  1... .... = SEG: 1 (分段消息)")
        lines.append(f"  .000 0000 = OpCode: 0")

        # 字节1: SZMIC(1位) + SeqZero的高位(7位)
        szmic_bit = (byte1 >> 7) & 1
        seq_zero_high = byte1 & 0x7F
        lines.append(f"字节1: {byte1:02x} = {byte1:08b}")
        lines.append(f"  {szmic_bit}... .... = SZMIC: {'64-bit' if szmic_bit else '32-bit'} ({szmic_bit})")
        lines.append(f"  .{seq_zero_high:07b} = SeqZero高7位: {seq_zero_high}")

        # 字节2: SeqZero的中位(6位) + SegO的高位(2位)
        seq_zero_mid = (byte2 >> 2) & 0x3F
        seg_o_high = byte2 & 0x03
        lines.append(f"字节2: {byte2:02x} = {byte2:08b}")
        lines.append(f"  {seq_zero_mid:06b}.. = SeqZero中6位: {seq_zero_mid}")
        lines.append(f"  ....{seg_o_high:02b} = SegO高2位: {seg_o_high}")

        # 字节3: SegO的低位(3位) + SegN(5位)
        seg_o_low = (byte3 >> 5) & 0x07
        seg_n_actual = (byte3 >> 3) & 0x1F
        rfu = byte3 & 0x07
        lines.append(f"字节3: {byte3:02x} = {byte3:08b}")
        lines.append(f"  {seg_o_low:03b}. .... = SegO低3位: {seg_o_low}")
        lines.append(f"  ...{seg_n_actual:05b} = SegN: {seg_n_actual}")
        lines.append(f"  .... .000 = RFU: {rfu}")

        # 验证重组的值
        reconstructed_seq_zero = (seq_zero_high << 6) | seq_zero_mid
        reconstructed_seg_o = (seg_o_high << 3) | seg_o_low

        lines.append(f"\n重组的值:")
        lines.append(f"  SZMIC: {szmic_bit}")
        lines.append(f"  SeqZero: {reconstructed_seq_zero} (原值: {seq_zero})")
        lines.append(f"  SegO: {reconstructed_seg_o} (原值: {seg_o})")
        lines.append(f"  SegN: {seg_n_actual} (原值: {seg_n})")

        formatted_output = "\n".join(lines)

        return header_bytes, formatted_output

    def reassemble_segments(self, segments):
        """重组分段

        Args:
            segments: 分段列表，按SegO排序

        Returns:
            bytes: 重组后的Upper Transport PDU
        """
        if not segments:
            return b''

        # 检查段的连续性和完整性
        segments_sorted = sorted(segments, key=lambda x: x['seg_o'])

        # 验证段序号连续性
        expected_seg_n = segments_sorted[-1]['seg_n']
        for i, segment in enumerate(segments_sorted):
            if segment['seg_o'] != i:
                raise ValueError(f"段序号不连续，期望{i}，实际{segment['seg_o']}")
            if segment['seg_n'] != expected_seg_n:
                raise ValueError(f"段总数不一致")

        # 验证是否所有段都收到
        if len(segments_sorted) != expected_seg_n + 1:
            raise ValueError(f"段不完整，期望{expected_seg_n + 1}段，实际{len(segments_sorted)}段")

        # 重组数据
        reassembled_data = b''
        for segment in segments_sorted:
            reassembled_data += segment['segment_data']

        return reassembled_data


class MeshDecrypter(object):
    def __init__(self, appkeys=None, devkeys=None, netkeys=None, ):
        if appkeys is None:
            self.appkeys = []
        else:
            self.appkeys = appkeys
        if devkeys is None:
            self.devkeys = []
        else:
            self.devkeys = devkeys
        if netkeys is None:
            self.netkeys = []
        else:
            self.netkeys = netkeys
        # 用于存储分段消息：key = (src, dst, seqzero), value = {segments: [], seg_n: int}
        self.segmented_messages = {}

    def set_appkey(self, appkey):
        self.appkeys.append(appkey)

    def set_devkey(self, devkey):
        self.devkeys.append(devkey)

    def set_netkey(self, netkey):
        self.netkeys.append(netkey)

    def get_appkeys(self):
        return self.appkeys

    def get_devkeys(self):
        return self.devkeys

    def get_netkeys(self):
        return self.netkeys

    def decrypt(self, pdu):
        MESH_MESSAGE_MIN_LENGTH = 17
        if (not isinstance(pdu, bytes) or
                len(pdu) < MESH_MESSAGE_MIN_LENGTH):
            return (pdu, 0, None)

        ivi = pdu[0] & 0x01
        nid = pdu[0] & 0x7f
        seqzero = None

        # 网络层解密
        cleartext = None
        netkey = None
        for key in self.netkeys:
            # Only run deobfuscation and decrypt if the NID matches
            if key.nid == nid:
                pdu_deobfuscated = key.deobfuscate(pdu)
                cleartext = key.decrypt(pdu_deobfuscated)
                if cleartext is not None:
                    netkey = key
                    pdu = cleartext
                    break
        if not (cleartext and netkey):
            print("Network layer decryption failed")
            return (pdu, 0, None)
        # print(f"decrypt network pdu: {pdu.hex()}")
        ctl = (pdu[1] & 0x80) > 0
        seg = (pdu[9] & 0x80) > 0
        akf = (pdu[9] & 0x40) > 0
        aid = (pdu[9] & 0x3f)
        cleartext = None
        segment_count = 1  # 默认非分段消息为1段
        # 如果为分段消息,并且有相同的seq zero，添加到数据组里面，前面为 key=seqzero编号，后面为value=packet，分段列表，packet按SegO排序，如果片段完整后,需要将分段消息重组为完整消息，
        if seg:
            # 提取分段消息的关键字段
            seq = pdu[2:5]
            src = pdu[5:7]
            dst = pdu[7:9]
            
            # 从传输层头部提取分段信息
            bytes_10_13 = int.from_bytes(pdu[10:13], 'big')
            szmic = (bytes_10_13 & 0x800000) >> 23
            seqzero = (bytes_10_13 & 0x7ffc00) >> 10
            sego = (bytes_10_13 & 0x0003e0) >> 5
            segn = (bytes_10_13 & 0x00001f)
            segment_count = segn + 1  # 分段消息的总段数
            
            # 使用 (src, dst, seqzero) 作为唯一标识
            seg_key = (src, dst, seqzero)
            
            # 初始化或获取分段消息组
            if seg_key not in self.segmented_messages:
                self.segmented_messages[seg_key] = {
                    'segments': {},  # key: sego, value: segment_pdu
                    'seg_n': segn,
                    'szmic': szmic
                }
            
            # 添加当前分段到组中
            seg_group = self.segmented_messages[seg_key]
            seg_group['segments'][sego] = pdu
            
            # 检查是否收集完整（0 到 seg_n 的所有片段）
            if len(seg_group['segments']) == segn + 1:
                # 按 SegO 排序并重组
                sorted_segos = sorted(seg_group['segments'].keys())
                
                # 验证片段连续性
                if sorted_segos == list(range(segn + 1)):
                    # print(f"分段消息完整，开始重组 SeqZero={seqzero:#x}, 共{segn+1}段")
                    
                    # 确定NetMIC长度
                    first_segment = seg_group['segments'][0]
                    if (first_segment[1] & 0x80) > 0:  # CTL bit检查
                        net_mic_len = 8
                    else:
                        net_mic_len = 4
                    
                    # 重组传输层PDU：拼接所有分段的 payload（去除网络头、传输头和NetMIC）
                    reassembled_transport_pdu = b''
                    for i in range(segn + 1):
                        segment_pdu = seg_group['segments'][i]
                        # 提取分段数据（跳过网络层头部9字节+传输层头部4字节，并去除NetMIC）
                        segment_payload = segment_pdu[13:-net_mic_len]
                        reassembled_transport_pdu += segment_payload
                    
                    # 使用第一个分段构建完整PDU
                    # 提取第一个分段的NetMIC
                    net_mic = first_segment[-net_mic_len:]
                    
                    # 重构完整PDU: 网络层头部(9字节) + 非分段传输层头部(1字节AKF+AID) + 重组后的加密payload + NetMIC
                    # 清除SEG标志位，构建非分段格式的传输层头部
                    transport_header = first_segment[9] & 0x7F  # 清除SEG位 (bit 7)
                    pdu = first_segment[0:9] + bytes([transport_header]) + reassembled_transport_pdu + net_mic
                    
                    # 保存SZMIC和SeqZero信息，用于后续的ApplicationKey/DeviceKey解密
                    reassembled_szmic = szmic
                    reassembled_seqzero = seqzero
                    
                    # 清理已处理的分段消息
                    del self.segmented_messages[seg_key]
                    
                    # print(f"重组后的PDU: {pdu.hex()}")
                    # print(f"  重组payload长度: {len(reassembled_transport_pdu)}, NetMIC: {net_mic.hex()}, SZMIC: {szmic}, SeqZero: {seqzero:#x}")
                    
                    # 更新标志位，让重组后的PDU继续走解密流程
                    seg = False
                    akf = (transport_header & 0x40) > 0
                    aid = transport_header & 0x3f
                    seqzero = reassembled_seqzero
                    # segment_count 已经在上面设置为 segn + 1，保持不变
                else:
                    print(f"分段消息不连续，等待更多片段")
                    return (None, segment_count, seqzero)
            else:
                # 片段未收集完整，返回None等待更多片段
                # print(f"收到分段 SegO={sego}/{segn}, SeqZero={seqzero:#x}, 等待更多片段 ({len(seg_group['segments'])}/{segn+1})")
                return (None, segment_count, seqzero)

        if ctl:
            print(f"this is a control message")
            return (pdu, segment_count, seqzero)

        if akf:
            # print(f"尝试AppKey解密, AKF={akf}, AID={aid:#x}, SEG={seg}")
            for key in self.appkeys:
                # 处理 AID 类型：appkey.aid 可能是 bytes 或 int
                appkey_aid = key.aid if isinstance(key.aid, int) else key.aid[0]
                # print(f"检查AppKey, AID={appkey_aid:#x}")
                if appkey_aid == aid:
                    # print(f"找到匹配的AppKey")
                    # 提取必要的参数进行ApplicationKey解密
                    seq = pdu[2:5]
                    src = pdu[5:7]
                    dst = pdu[7:9]
                    iv_index = netkey.iv_index
                    
                    # 确定 szmic 和 seqzero（从重组保存的信息或PDU中提取）
                    if 'reassembled_szmic' in locals():
                        szmic = reassembled_szmic
                        seqzero = reassembled_seqzero if 'reassembled_seqzero' in locals() else None
                    elif seg:
                        # 分段消息：从 PDU[10:13] 提取 szmic 和 seqzero
                        bytes_10_13 = int.from_bytes(pdu[10:13], 'big')
                        szmic = (bytes_10_13 & 0x800000) >> 23
                        seqzero = (bytes_10_13 & 0x7ffc00) >> 10
                    else:
                        szmic = 0  # 非分段消息默认使用32-bit TransMIC
                        seqzero = None

                    # NetworkKey.decrypt 返回的 PDU 格式：
                    # pdu[0:7] + cleartext + NetMIC
                    # 其中 cleartext = DST + TransportPDU
                    # 所以完整格式是: [0:7] + [7:9](DST) + [9:-4](TransportPDU) + [-4:](NetMIC)
                    # ApplicationKey.decrypt 需要完整的 PDU（包含网络层头部和 AKF+AID）
                    # 对于非分段消息，需要去除 NetMIC
                    if (pdu[1] & 0x80) > 0:  # CTL bit检查
                        net_mic_len = 8
                    else:
                        net_mic_len = 4
                    # 去除 NetMIC，构建完整的 PDU 用于 ApplicationKey.decrypt
                    # ApplicationKey.decrypt 期望: [0:9](网络层头部+DST+AKF+AID) + [9:](UpperTransportPDU包含TransMIC)
                    full_app_pdu = pdu[:-net_mic_len]  # 去除 NetMIC
                    
                    # print(f"AppKey解密输入: {full_app_pdu.hex()}, szmic={szmic}, seqzero={seqzero:#x if seqzero else 'None'}")
                    cleartext = key.decrypt(szmic, seqzero, seq, src, dst, iv_index, full_app_pdu)
                    if cleartext is not None:
                        # 重建PDU：保留网络层和传输层头部，替换Access PDU部分
                        if seg:
                            pdu = pdu[0:13] + cleartext
                        else:
                            pdu = pdu[0:10] + cleartext
                        break
        else:
            # DeviceKey 解密 (AKF=0, AID=0)
            # print(f"尝试DeviceKey解密, AKF={akf}, AID={aid}, SEG={seg}")
            for key in self.devkeys:
                if netkey is not None:
                    # 提取必要的参数进行DeviceKey解密
                    seq = pdu[2:5]
                    src = pdu[5:7]
                    dst = pdu[7:9]
                    iv_index = netkey.iv_index
                    
                    # 确定 szmic（从 PDU 中提取，如果是分段消息）
                    szmic = 0
                    if seg:
                        # 分段消息：从 PDU[10:13] 提取 szmic
                        bytes_10_13 = int.from_bytes(pdu[10:13], 'big')
                        szmic = (bytes_10_13 & 0x800000) >> 23
                    
                    # NetworkKey.decrypt 返回的 PDU 格式：
                    # pdu[0:7] + cleartext + NetMIC
                    # 其中 cleartext = DST + TransportPDU
                    # 所以完整格式是: [0:7] + [7:9](DST) + [9:-4](TransportPDU) + [-4:](NetMIC)
                    # DeviceKey.decrypt 需要完整的 PDU（包含网络层头部和 AKF+AID）
                    # 对于非分段消息，需要去除 NetMIC
                    if (pdu[1] & 0x80) > 0:  # CTL bit检查
                        net_mic_len = 8
                    else:
                        net_mic_len = 4
                    # 去除 NetMIC，构建完整的 PDU 用于 DeviceKey.decrypt
                    # DeviceKey.decrypt 期望: [0:9](网络层头部+DST+AKF+AID) + [9:](UpperTransportPDU包含TransMIC)
                    full_dev_pdu = pdu[:-net_mic_len]  # 去除 NetMIC
                    
                    # print(f"DeviceKey解密输入PDU: {full_dev_pdu.hex()}, szmic={szmic}")
                    cleartext = key.decrypt(szmic, seq, src, dst, iv_index, full_dev_pdu)
                    if cleartext is not None:
                        # print(f"DeviceKey解密成功: {cleartext.hex()}")
                        # 重建PDU：保留网络层和传输层头部，替换Access PDU部分
                        if seg:
                            pdu = pdu[0:13] + cleartext
                        else:
                            pdu = pdu[0:10] + cleartext
                        break
                    # else:
                    #     print("DeviceKey解密失败")
        return (pdu, segment_count, seqzero)

    def encrypt(self, pdu):

        if (not isinstance(pdu, bytes)):
            return

        ivi = pdu[0] & 0x01  # iv index last bit
        nid = pdu[0] & 0x7f  # network id
        ctl = pdu[1] & 0x80  # control message netmic size 0 32bit  Access message 1 64bit Transport Control message
        ttl = pdu[1] & 0x7f  # time to live
        seq = pdu[2:5]
        src = pdu[5:7]
        dst = pdu[7:9]
        self.upper_transport_segmenter = UpperTransportSegmenter(ivi)

        # Use the first network key directly without NID matching check
        # This allows encryption with any NID specified in the PDU
        if len(self.netkeys) == 0:
            print("Error: No NetworkKey available")
            return None
        
        netkey = self.netkeys[0]  # Use the first network key
        # application key encrypt
        if ctl:
            # It's a transport control message, i.e., unencrypted by the transport layer.
            segments = self.upper_transport_segmenter.segment_upper_transport_pdu(0, seq, is_control=True)
            TransportPDUList = [pdu[9:]]  # Use the transport PDU as-is for control messages
        else:
            seg = pdu[9] & 0x80  # segment flag
            akf = pdu[9] & 0x40  # application key flag
            aid = pdu[9] & 0x3f  # application key identifier
            if akf:
                TransportPDUList = []
                print(f"ApplicationKey加密 - akf={akf}, aid=0x{aid:02x}")
                for appkey in self.appkeys:
                    # 处理 AID 类型：appkey.aid 可能是 bytes 或 int
                    appkey_aid = appkey.aid if isinstance(appkey.aid, int) else appkey.aid[0]
                    print(f"检查AppKey AID: 0x{appkey_aid:02x}")
                    print(f"aid: 0x{aid:02x}")
                    print(f"appkey_aid: 0x{appkey_aid:02x}")
                    if appkey_aid == aid:
                        print(f"找到匹配的AppKey！")
                        # print(f"seg={seg}, pdu[9]=0x{pdu[9]:02x}")
                        # print(f"pdu[10:] (要加密的数据): {pdu[10:].hex()}")
                        # print(f"seq={seq.hex()}, src={src.hex()}, dst={dst.hex()}")
                        if seg:
                            # print(f"分段消息: szmic=0x{szmic:02x}")
                            seq_auth = self.upper_transport_segmenter.calculate_seq_auth(seq, netkey.iv_index)
                            seq_zero = self.upper_transport_segmenter.calculate_seq_zero(seq_auth)
                            encryp_text = appkey.encrypt(
                                seq=seq,
                                src=src,
                                dst=dst,
                                iv_index=netkey.iv_index,
                                pdu=pdu,seq_zero=seq_zero)
                            # TransportPDUList = pdu[9:13] + encryp_text

                            segments = self.upper_transport_segmenter.segment_upper_transport_pdu(encryp_text,
                                                                                                  seq, szmic=(pdu[10] & 0x80) >> 7,
                                                                                                  is_control=False)
                            for segment in segments:
                                segment_array = bytearray(segment)
                                segment_array[0] = pdu[9]
                                modified_segment = bytes(segment_array)
                                print(f"modified_segment: {modified_segment.hex()}")
                                TransportPDUList.append(modified_segment)
                        else:
                            encryp_text = appkey.encrypt(
                                seq=seq,
                                src=src,
                                dst=dst,
                                iv_index=netkey.iv_index,
                                pdu=pdu)
                            TransportPDUList.append(pdu[9:10] + encryp_text)
                        break
            else:
                TransportPDUList = []
                for key in self.devkeys:
                    seq_auth = self.upper_transport_segmenter.calculate_seq_auth(seq, netkey.iv_index)
                    seq_zero = self.upper_transport_segmenter.calculate_seq_zero(seq_auth)
                    encryp_text = key.encrypt(
                            seq=seq,
                            src=src,
                            dst=dst,
                            iv_index=netkey.iv_index,
                            pdu=pdu, seq_zero=seq_zero)
                    print(f"encryp_text: {encryp_text.hex()}")
                    if seg:

                        segments = self.upper_transport_segmenter.segment_upper_transport_pdu(encryp_text, seq,
                                                                                              szmic=(pdu[10] & 0x80) >> 7,
                                                                                              is_control=False)
                        for segment in segments:
                            # 转换为bytearray以允许修改，然后修改第一个字节，再转换回bytes
                            segment_array = bytearray(segment)
                            segment_array[0] = pdu[9]
                            modified_segment = bytes(segment_array)
                            print(f"modified_segment: {modified_segment.hex()}")
                            TransportPDUList.append(modified_segment)
                    else:
                        # encryp_text = key.encrypt(
                        #     seq=seq,
                        #     src=src,
                        #     dst=dst,
                        #     iv_index=netkey.iv_index,
                        #     pdu=pdu)
                        TransportPDUList.append(pdu[9:10] + encryp_text)
                    break

        # network key encrypt
        # 检查 TransportPDUList 是否为空
        if not TransportPDUList:
            print(f"Error: No matching key found for encryption. akf={akf}, aid=0x{aid:02x}")
            print("请确保PDU中的AID与可用的AppKey AID匹配")
            return None
        
        # 如果是分段消息，需要为每个Transport PDU进行网络层加密
        network_pdu_list = []
        if len(TransportPDUList) > 1:
            # 分段情况：为每个Transport PDU创建网络PDU
            for transport_pdu in TransportPDUList:
                pdu = pdu[0:2] + seq + pdu[5:]
                plain_network_pdu = pdu[0:9] + transport_pdu
                print(f"分段plain_network_pdu: {plain_network_pdu.hex()}")
                plaintext, encry_pdu = netkey.encrypt(iv_index=netkey.iv_index, pdu=plain_network_pdu)
                obfuscated_pdu = netkey.obfuscate(plaintext[1:7], encry_pdu)
                en_network_pdu = plaintext[0].to_bytes(1, 'big') + obfuscated_pdu + encry_pdu
                seq = (int.from_bytes(seq, 'big') + 1).to_bytes(3, 'big')
                network_pdu_list.append(en_network_pdu)

            # print(f"分段网络PDU列表: {[pdu.hex() for pdu in network_pdu_list]}")
            return network_pdu_list
        else:
            # 非分段情况：单个Transport PDU
            TransportPDU = TransportPDUList[0] if TransportPDUList else b''
            plain_network_pdu = pdu[0:9] + TransportPDU
            print(f"plain_network_pdu: {plain_network_pdu.hex()}")
            plaintext, encry_pdu = netkey.encrypt(iv_index=netkey.iv_index, pdu=plain_network_pdu)
            obfuscated_pdu = netkey.obfuscate(plaintext[1:7], encry_pdu)
            network_pdu_list.append(plaintext[0].to_bytes(1, 'big') + obfuscated_pdu + encry_pdu)
            return network_pdu_list



def test_devkey_encrypt():
    from utils import key
    devkey_bytes = bytes.fromhex('e6ce64c56af28568333730791549a2ca')
    devkey = key.DeviceKey(devkey_bytes, 0x0005)
    ivi_nid = bytes.fromhex('59')
    ctl_ttl = bytes.fromhex('03')
    seq = bytes.fromhex('000000')
    src = bytes.fromhex('0001')
    dst = bytes.fromhex('0005')
    iv_index = 0
    akf_aid = bytes.fromhex('00')
    pdu = bytes.fromhex('800800')

    test_pdu = ivi_nid + ctl_ttl + seq + src + dst + akf_aid + pdu
    encrypted_pdu = devkey.encrypt(seq, src, dst, iv_index, test_pdu)
    print(f"encrypted_pdu: {encrypted_pdu.hex()}")

    netkey_bytes = bytes.fromhex('aed421e6dd9432a3f3b7e03c5fd771ce')
    test_network_pdu = ivi_nid + ctl_ttl + seq + src + dst + akf_aid + encrypted_pdu
    netkey = key.NetworkKey(netkey_bytes, 0)
    plaintext, encry_pdu = netkey.encrypt(iv_index=netkey.iv_index, pdu=test_network_pdu)
    obfuscated_pdu = netkey.obfuscate(plaintext[1:7], encry_pdu)
    network_pdu = plaintext[0].to_bytes(1, 'big') + obfuscated_pdu + encry_pdu
    print(f"network_pdu: {network_pdu.hex()}")

    ble_mesh_decrypter = MeshDecrypter()
    ble_mesh_decrypter.set_netkey(netkey)
    ble_mesh_decrypter.set_devkey(devkey)

    encrypted_pdu = ble_mesh_decrypter.encrypt(test_pdu)
    print(f"encrypted_pdu: {encrypted_pdu[0].hex()}")



def test_appkey_encrypt():

    appkey_bytes = bytes.fromhex('12121212121212121212121212121212')
    appkey = key.ApplicationKey(appkey_bytes)

    ivi_nid = bytes.fromhex('59')
    ctl_ttl = bytes.fromhex('03')
    seq = bytes.fromhex('000005')
    src = bytes.fromhex('0001')
    dst = bytes.fromhex('0005')
    iv_index = 0
    akf_aid = bytes.fromhex('4B')
    pdu = bytes.fromhex('8201')

    test_pdu = ivi_nid + ctl_ttl + seq + src + dst + akf_aid + pdu
    encrypted_pdu = appkey.encrypt(seq, src, dst, iv_index, test_pdu)
    print(f"encrypted_pdu: {encrypted_pdu.hex()}")

    netkey_bytes = bytes.fromhex('aed421e6dd9432a3f3b7e03c5fd771ce')
    test_network_pdu = ivi_nid + ctl_ttl + seq + src + dst + akf_aid + encrypted_pdu
    netkey = key.NetworkKey(netkey_bytes, 0)
    plaintext, encry_pdu = netkey.encrypt(iv_index=netkey.iv_index, pdu=test_network_pdu)
    obfuscated_pdu = netkey.obfuscate(plaintext[1:7], encry_pdu)
    network_pdu = plaintext[0].to_bytes(1, 'big') + obfuscated_pdu + encry_pdu
    print(f"network_pdu: {network_pdu.hex()}")

    ble_mesh_decrypter = MeshDecrypter()
    ble_mesh_decrypter.set_netkey(netkey)
    ble_mesh_decrypter.set_appkey(appkey)

    encrypted_pdu = ble_mesh_decrypter.encrypt(test_pdu)
    print(f"encrypted_pdu: {encrypted_pdu[0].hex()}")


def test_devkey_decrypt():
    devkey_bytes = bytes.fromhex('e6ce64c56af28568333730791549a2ca')
    netkey_bytes = bytes.fromhex('aed421e6dd9432a3f3b7e03c5fd771ce')
    netkey = key.NetworkKey(netkey_bytes, 0)
    devkey = key.DeviceKey(devkey_bytes, 0x0005)
    encrypted_pdu = bytes.fromhex('59e2548e3e18aa1c05a206583b981b5db46a32b782')
    ble_mesh_decrypter = MeshDecrypter()
    ble_mesh_decrypter.set_netkey(netkey)
    ble_mesh_decrypter.set_devkey(devkey)
    decrypted_pdu, segment_count, seqzero = ble_mesh_decrypter.decrypt(encrypted_pdu)
    print(f"decrypted_pdu: {decrypted_pdu.hex()}, segment_count: {segment_count}, seqzero: {seqzero}")
    decrypted_pdu, segment_count, seqzero = ble_mesh_decrypter.decrypt(encrypted_pdu)
    print(f"decrypted_pdu: {decrypted_pdu.hex()}, segment_count: {segment_count}, seqzero: {seqzero}")

def test_appkey_decrypt():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0,os.path.dirname(os.path.abspath(__file__)) + "/../libs/")
    from scapy.contrib.ble_mesh import Message_Decode
    appkey_bytes = bytes.fromhex('12121212121212121212121212121212')
    netkey_bytes = bytes.fromhex('aed421e6dd9432a3f3b7e03c5fd771ce')
    netkey = key.NetworkKey(netkey_bytes, 0)
    appkey = key.ApplicationKey(appkey_bytes)
    encrypted_pdu = bytes.fromhex('590578c49fa99d57fc684e51a427173646e33cbe')
    ble_mesh_decrypter = MeshDecrypter()
    ble_mesh_decrypter.set_netkey(netkey)
    ble_mesh_decrypter.set_appkey(appkey)
    decrypted_pdu, segment_count = ble_mesh_decrypter.decrypt(encrypted_pdu)
    pkt = Message_Decode(decrypted_pdu)
    pkt.show()

    print(f"decrypted_pdu: {decrypted_pdu.hex()}, segment_count: {segment_count}")

## 分段的数据包测试
def test_segmented_devkey_pdu():
    from utils import key
    netkey_bytes = bytes.fromhex('aed421e6dd9432a3f3b7e03c5fd771ce')
    netkey = key.NetworkKey(netkey_bytes, 0)
    devkey_bytes = bytes.fromhex('e6ce64c56af28568333730791549a2ca')
    devkey = key.DeviceKey(devkey_bytes, 0x0005)
    ivi_nid = bytes.fromhex('59')
    ctl_ttl = bytes.fromhex('03')
    seq = bytes.fromhex('000002')  # 修改为 0x000002 以使 SeqZero=2
    src = bytes.fromhex('0001')
    dst = bytes.fromhex('0005')
    akf_aid = bytes.fromhex('80')
    # 分段头部: SZMIC=0, SeqZero=2, SegO=0(第1段), SegN=1(共2段)
    szmic_last = bytes.fromhex('000801')  # 修正: SegO应该是0而不是1
    pdu = bytes.fromhex('0000000012121212121212121212121212121212')

    test_pdu = ivi_nid + ctl_ttl + seq + src + dst + akf_aid + szmic_last + pdu
    #使用mesh_decrypter.encrypt方法
    ble_mesh_decrypter = MeshDecrypter()
    ble_mesh_decrypter.set_devkey(devkey)
    ble_mesh_decrypter.set_netkey(netkey)
    encrypted_pdu = ble_mesh_decrypter.encrypt(test_pdu)
    print(f"encrypted_pdu: {encrypted_pdu[0].hex()}")
    print(f"encrypted_pdu: {encrypted_pdu[1].hex()}")

def test_segmented_devdey_decrypt_pdu():
    from utils import key
    # 导入 scapy 的 BLEMesh_Message 用于解析解密后的 PDU
    try:
        from scapy.contrib.ble_mesh import Message_Decode
    except ImportError:
        print("警告: 无法导入 scapy.contrib.ble_mesh，将只显示原始字节")
        Message_Decode = None
    netkey_bytes = bytes.fromhex('aed421e6dd9432a3f3b7e03c5fd771ce')
    netkey = key.NetworkKey(netkey_bytes, 0)
    devkey_bytes = bytes.fromhex('e6ce64c56af28568333730791549a2ca')
    devkey = key.DeviceKey(devkey_bytes, 0x0005)
    encrypted_pdus = []
    encrypted_pdus.append(bytes.fromhex('59cb0f52e4711205cfda62b06dfed679dd9ef9d5632fa89968b9a94614'))
    encrypted_pdus.append(bytes.fromhex('595d5e33d4f2086c5ad00fe94f7b235e7aa31df5f2ed24ad86cf957e28'))
    
    ble_mesh_decrypter = MeshDecrypter()
    ble_mesh_decrypter.set_netkey(netkey)
    ble_mesh_decrypter.set_devkey(devkey)
    
    # 逐个处理分段消息
    decrypted_pdu = None
    segment_count = 0
    for encrypted_pdu in encrypted_pdus:
        result, seg_count, seqzero = ble_mesh_decrypter.decrypt(encrypted_pdu)
        segment_count = seg_count  # 保存分段数量
        if result is not None:
            decrypted_pdu = result
            break  # 收集完所有分段后会返回重组结果
    
    if decrypted_pdu:
        print(f"最终解密的完整PDU: {decrypted_pdu.hex()}, segment_count: {segment_count}")
        print(f"Access Message: {decrypted_pdu[10:].hex()}")
        
        # 使用 scapy 解析 PDU
        if Message_Decode is not None:
            try:
                print("\n使用 scapy 解析 PDU:")
                pkt = Message_Decode(decrypted_pdu)
                pkt.show()
            except Exception as e:
                print(f"解析失败: {e}")
    else:
        print("解密失败或分段未收集完整")


def test_segmented_appkey_pdu():
    """测试AppKey分段消息加密"""
    from utils import key
    # 根据图片中的参数设置
    netkey_bytes = bytes.fromhex('7dd7364cd842ad18c17c2b820c84c3d6')
    netkey = key.NetworkKey(netkey_bytes, 0x12345677)  # IV Index
    appkey_bytes = bytes.fromhex('639647717341fbd76e3b40519d1d94a4')  # 16字节AppKey
    appkey = key.ApplicationKey(appkey_bytes)
    
    # 构造测试PDU
    ivi_nid = bytes.fromhex('e8')  # IVI=1, NID=0x68
    ctl_ttl = bytes.fromhex('03')
    seq = bytes.fromhex('07080d')  # SEQ，SeqZero = 0x80d
    src = bytes.fromhex('1234')
    dst = bytes.fromhex('9736')
    
    # AKF=1 (bit 6), 使用AppKey计算的AID
    # SEG=1 (bit 7) 需要设置分段标志
    aid_value = appkey.aid[0] if isinstance(appkey.aid, bytes) else appkey.aid
    akf_aid_value = 0x80 | 0x40 | aid_value  # SEG=1, AKF=1, AID
    akf_aid = bytes([akf_aid_value])
    
    # 分段头部: SZMIC=1(64-bit), SeqZero=0x80d, SegO=0, SegN=1
    seqzero = 0x80d
    szmic = 1
    sego = 0
    segn = 1
    seg_header = (szmic << 23) | (seqzero << 10) | (sego << 5) | segn
    szmic_last = seg_header.to_bytes(3, 'big')
    
    # Access message payload
    pdu = bytes.fromhex('ea0a00576f726c64')
    
    test_pdu = ivi_nid + ctl_ttl + seq + src + dst + akf_aid + szmic_last + pdu
    
    print(f"原始PDU: {test_pdu.hex()}")
    print(f"Access Message: {pdu.hex()}")
    
    # 使用mesh_decrypter.encrypt方法
    ble_mesh_decrypter = MeshDecrypter()
    ble_mesh_decrypter.set_appkey(appkey)
    ble_mesh_decrypter.set_netkey(netkey)
    encrypted_pdu = ble_mesh_decrypter.encrypt(test_pdu)
    if encrypted_pdu:
        print(f"加密分段1: {encrypted_pdu[0].hex()}")
        if len(encrypted_pdu) > 1:
            print(f"加密分段2: {encrypted_pdu[1].hex()}")

def test_segmented_appkey_decrypt_pdu():
    """测试AppKey分段消息解密"""
    from utils import key
    # 导入 scapy 的 Message_Decode 用于解析解密后的 PDU
    try:
        from scapy.contrib.ble_mesh import Message_Decode
    except ImportError:
        print("警告: 无法导入 scapy.contrib.ble_mesh，将只显示原始字节")
        Message_Decode = None
    netkey_bytes = bytes.fromhex('7dd7364cd842ad18c17c2b820c84c3d6')
    netkey = key.NetworkKey(netkey_bytes, 0x12345677)
    appkey_bytes = bytes.fromhex('639647717341fbd76e3b40519d1d94a4')  # 16字节AppKey
    appkey = key.ApplicationKey(appkey_bytes)
    
    # 使用我们刚才加密生成的PDU来测试解密
    encrypted_pdus = []
    encrypted_pdus.append(bytes.fromhex('e81d37be16f16c94e99fb4081f637d958e5972ef35b1d180fe20a62dbd'))
    encrypted_pdus.append(bytes.fromhex('e8a3e0b7224b2fdc2f4ad6fb4d38029d31b0434488'))
    
    ble_mesh_decrypter = MeshDecrypter()
    ble_mesh_decrypter.set_netkey(netkey)
    ble_mesh_decrypter.set_appkey(appkey)
    
    # 逐个处理分段消息
    decrypted_pdu = None
    segment_count = 0
    for encrypted_pdu in encrypted_pdus:
        result, seg_count, seqzero = ble_mesh_decrypter.decrypt(encrypted_pdu)
        segment_count = seg_count  # 保存分段数量
        if result is not None:
            decrypted_pdu = result
            break  # 收集完所有分段后会返回重组结果
    
    if decrypted_pdu:
        print(f"AppKey最终解密的完整PDU: {decrypted_pdu.hex()}, segment_count: {segment_count}")
        print(f"Access Message: {decrypted_pdu[10:].hex()}")
        
        # 使用 scapy 解析 PDU
        if Message_Decode is not None:
            try:
                print("\n使用 scapy 解析 PDU:")
                pkt = Message_Decode(decrypted_pdu)
                pkt.show()
            except Exception as e:
                print(f"解析失败: {e}")
    else:
        print("AppKey解密失败或分段未收集完整")


if __name__ == "__main__":
    # 测试 DevKey 分段消息
    # test_segmented_devkey_pdu()  # 测试DevKey加密
    # test_segmented_devdey_decrypt_pdu()  # 测试DevKey解密
    
    # 测试 AppKey 分段消息
    # print("=== AppKey 分段消息加密测试 ===")
    # test_appkey_decrypt() # 测试AppKey加密
    # print()
    # print("=== AppKey 分段消息解密测试 ===")
    test_segmented_appkey_decrypt_pdu()  # 测试AppKey解密
    
    # print("BLE Mesh Decrypter 模块加载成功")
    # print("可用的测试函数:")
    # print("  - test_segmented_devkey_pdu()          # DevKey 分段消息加密")
    # print("  - test_segmented_devdey_decrypt_pdu()  # DevKey 分段消息解密")
    # print("  - test_segmented_appkey_pdu()          # AppKey 分段消息加密")
    # print("  - test_segmented_appkey_decrypt_pdu()  # AppKey 分段消息解密")




