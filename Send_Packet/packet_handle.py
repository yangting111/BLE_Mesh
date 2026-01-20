#写一个class，包括几个函数，可对raw bytes添加或者减少固定的bytes，并返回处理后的bytes，参数为bytes数量，随机生成bytes，并添加到raw bytes中
import random
class Packet_Handle():
    def __init__(self):
        pass
    def get_random_bytes(self,bytes_number):
        return bytes(random.randint(0, 255) for _ in range(bytes_number))

    def add_bytes(self,raw_bytes,bytes_number):
        return raw_bytes + self.get_random_bytes(bytes_number)

    def remove_bytes(self,raw_bytes,bytes_number):
        return raw_bytes[:-bytes_number]

    # 如果参数为add，则添加随机bytes，如果参数为remove，则删除随机bytes
    def handle_bytes(self,mode,raw_bytes,bytes_number):
        if mode == "add":
            return self.add_bytes(raw_bytes,bytes_number)
        elif mode == "remove":
            return self.remove_bytes(raw_bytes,bytes_number)
        else:
            print("Error: mode is not valid")
            return None