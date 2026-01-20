


# 生成ECC密钥对
key1 = ECC.generate(curve='P-256')
key2 = ECC.generate(curve='P-256')

private_key1 = key1.d
private_key2 = key2.d  
public_key1 = key1.pointQ
public_key2 = key2.pointQ

# 将私钥转换为字符串
def private_key_to_string(private_key):
    private_key1_string = private_key.to_bytes(32, byteorder='big').hex()
    return private_key1_string
# 将公钥转换为字符串
def public_key_to_string(public_key):
    public_key1_string_x = int(public_key1.x).to_bytes(32, byteorder='big').hex()
    print(int(public_key1.x).to_bytes(32, byteorder='big'))
    public_key1_string_y = int(public_key1.y).to_bytes(32, byteorder='big').hex()
    return public_key1_string_x, public_key1_string_y

# 将字符串转换为私钥
def string_to_private_key(private_key_string):
    private_key_int = int.from_bytes(bytes.fromhex(private_key_string), byteorder='big')
    private_key = ECC.construct(curve='P-256', d=private_key_int)
    return private_key.d

# 将字符串转换为公钥
def string_to_public_key(public_key_string_x, public_key_string_y):
    public_key_int_x = int.from_bytes(bytes.fromhex(public_key_string_x), byteorder='big')
    public_key_int_y = int.from_bytes(bytes.fromhex(public_key_string_y), byteorder='big')
    public_key = ECC.construct(curve='P-256', point_x=public_key_int_x, point_y=public_key_int_y)
    return public_key.pointQ

def gen_ECDHSecretKey(private_key_string,device_public_key_string_x, device_public_key_string_y):
    # 计算ECDH的共享密钥
    private_key_int = int.from_bytes(bytes.fromhex(private_key_string), byteorder='big')
    pub_int_x = int.from_bytes(bytes.fromhex(device_public_key_string_x), byteorder='big')
    pub_int_y = int.from_bytes(bytes.fromhex(device_public_key_string_y), byteorder='big')
    private_key = ECC.construct(curve='P-256', d=private_key_int)
    device_public_key = ECC.construct(curve='P-256', point_x=pub_int_x, point_y=pub_int_y)
    shared_key = private_key.d * device_public_key.pointQ
    shared_key_byte = int(shared_key.x).to_bytes(32, byteorder='big')
    return shared_key_byte

