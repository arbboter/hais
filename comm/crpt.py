# -*- coding: utf-8 -*-
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64
import os
from comm import dirfile
from comm.slog import show
from comm.slog import show_exp

g_rsa_pri_tag = 'RSA PRIVATE'
g_rsa_pub_tag = 'PUBLIC'
g_rsa_reserve_size = 64


# 测试函数
def main():
    # 使用pycryptodome实现RSA的加解密和签名，函数均使用pkcs1和SHA-1
    # 读取RSA公钥私钥

    # 获取密钥PEM文件路径
    key_dir = dirfile.get_user_home_dir()
    key_size = 2048
    if key_size == 2048:
        rsa_pri_file = os.path.join(key_dir, 'rsa_private_key_2048.pem')
        rsa_pub_file = os.path.join(key_dir, 'rsa_public_key_2048.pem')
    else:
        rsa_pri_file = os.path.join(key_dir, 'rsa_private_key.pem')
        rsa_pub_file = os.path.join(key_dir, 'rsa_public_key.pem')

    # 通过标准key文件加载rsa需要的key
    rsa_pri_key = load_rsa_file(rsa_pri_file)
    rsa_pub_key = load_rsa_file(rsa_pub_file)

    # 公钥加密，私钥解密
    data = '''目前主流密钥长度至少都是1024bits以上，低于1024bit的密钥已经不建议使用（安全问题）。那么上限在哪里？
    没有上限，多大都可以使用。所以，主流的模值是1024位，实际运算结果可能会略小于1024bits，注意，这个值不是绝对的，
    跟素数的生成算法有关系，只是告诉素数生成器“帮我生成一个接近1024位的素数而已”，然后生成器“好，给您一个，这
    个差不多1024位”。'''

    enc_data = rsa_enc(data.encode(), rsa_pub_key)
    enc_data_base64 = base64_enc(enc_data)

    show('原始数据:', data)
    show('加密编码后的结果:', enc_data_base64)
    piain_data = rsa_dec(enc_data, rsa_pri_key)
    show('解密结果:', piain_data.decode())

    # 签名
    sig = rsa_sign(data.encode(), rsa_pri_key)
    show('签名结果:', sig)
    sig_ok = rsa_sign_verify(data.encode(), sig, rsa_pub_key)
    show('验证签名是否正确:', sig_ok)
    data += ' '
    sig_ok = rsa_sign_verify(data.encode(), sig, rsa_pub_key)
    show('验证签名是否正确:', sig_ok)


# base64编码
def base64_enc(data):
    ret_data = b''
    try:
        ret_data = base64.encodebytes(data)
    except Exception as err:
        show_exp('base64编码失败', '', err)
    return ret_data


# base64解码
def base64_dec(data):
    ret_data = b''
    try:
        ret_data = base64.decodebytes(data)
    except Exception as err:
        show_exp('base64解码失败', '', err)
    return ret_data


# 根据key长度计算分块大小
def get_block_size(rsa_key):
    try:
        # RSA仅支持限定长度内的数据的加解密，需要分块
        # 分块大小
        reserve_size = g_rsa_reserve_size
        key_size = rsa_key.size_in_bits()
        if (key_size % 8) != 0:
            raise RuntimeError('RSA 密钥长度非法')

        # 密钥用来解密，解密不需要预留长度
        if rsa_key.has_private():
            reserve_size = 0

        bs = 1024/8 - reserve_size
        bs = int(key_size/8) - reserve_size
    except Exception as err:
        show_exp('计算加解密数据块大小出错', rsa_key, err)
    return bs


# 返回块数据
def block_data(data, rsa_key):
    bs = get_block_size(rsa_key)
    for i in range(0, len(data), bs):
        yield data[i:i+bs]
    return


# RSA_加密
def rsa_enc(data, rsa_key):
    ciphertext = b''
    try:
        rsa_key = rsa_key_2std(rsa_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        for dat in block_data(data, rsa_key):
            cur_text = cipher.encrypt(dat)
            ciphertext += cur_text
    except Exception as err:
        show_exp('RSA加密失败', data, err)
    return ciphertext


# RSA解密
def rsa_dec(data, rsa_key):
    plaintext = b''
    try:
        rsa_key = rsa_key_2std(rsa_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        for dat in block_data(data, rsa_key):
            cur_text = cipher.decrypt(dat)
            plaintext += cur_text
    except Exception as err:
        show_exp('RSA解密失败', '', err)
    return plaintext


# RSA_加密
def pkcs8_rsa_enc(data, rsa_key):
    ciphertext = b''
    try:
        rsa_key = rsa_key_2std(rsa_key)
        cipher = PKCS1_v1_5.new(rsa_key)
        for dat in block_data(data, rsa_key):
            cur_text = cipher.encrypt(dat)
            ciphertext += cur_text
    except Exception as err:
        show_exp('RSA加密失败', data, err)
    return ciphertext


# RSA解密
def pkcs8_rsa_dec(data, rsa_key):
    plaintext = b''
    try:
        rsa_key = rsa_key_2std(rsa_key)
        cipher = PKCS1_v1_5.new(rsa_key)
        for dat in block_data(data, rsa_key):
            cur_text = cipher.decrypt(dat, "rsa加密出错")
            plaintext += cur_text
    except Exception as err:
        show_exp('RSA解密失败', '', err)
    return plaintext


# RSA签名
def rsa_sign(data, rsa_key):
    signature = ''
    try:
        h = SHA256.new(data)
        signature = pkcs1_15.new(rsa_key).sign(h)
    except Exception as err:
        show_exp('RSA签名失败', '', err)
    return signature


# RSA签名验证
def rsa_sign_verify(data, sig, rsa_key):
    try:
        h = SHA256.new(data)
        pkcs1_15.new(rsa_key).verify(h, sig)
        ret = True
    except (ValueError, TypeError):
        ret = False
    return ret


# 读取标准的rsa公私钥pem文件
def load_rsa_file(fn):
    key = None
    try:
        key = RSA.importKey(open(fn).read())
    except Exception as err:
        show_exp('导入rsa的KEY文件出错', fn, err)
    return key


# 标准字符串密钥转rsa格式密钥
def rsa_key_2std(skey):
    ret = None
    try:
        if type(skey) == RSA.RsaKey:
            ret = skey
        else:
            ret = RSA.importKey(skey)
    except Exception as err:
        show_exp('密钥转rsa格式错误', skey, err)
    return ret


# 生成标准rsa的key的标记
def make_key_tag(tag, beg=True):
    if beg:
        return '-----BEGIN ' + tag + ' KEY-----'
    else:
        return '-----END ' + tag + ' KEY-----'


# 生成标准的字符串格式key
def make_std_str_key(skey, pub=True):
    # 判断非标准时才继续
    if rsa_key_type(skey) != "unkonw":
        return skey
    tag = g_rsa_pub_tag
    if not pub:
        tag = g_rsa_pri_tag
    rsa_beg = make_key_tag(tag, True)
    rsa_dat = skey
    rsa_end = make_key_tag(tag, False)
    return '\n'.join([rsa_beg, rsa_dat, rsa_end])


# 根据字符串格式判断KEY的类型
def rsa_key_type(skey):
    std_pri_tag = make_key_tag(g_rsa_pri_tag, True)
    std_pub_tag = make_key_tag(g_rsa_pub_tag, True)

    if skey.startswith(std_pri_tag):
        return "private"
    elif skey.startswith(std_pub_tag):
        return "public"
    else:
        return "unknow"


if __name__ == '__main__':
    main()
