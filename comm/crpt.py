# -*- coding: utf-8 -*-
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15, PKCS1_v1_5 as PKCS1_v1_5_sign
from Crypto.Hash import SHA256
import base64
import os
from comm import dirfile
from comm.slog import show
from comm.slog import show_exp
import json

g_rsa_pri_tag = 'RSA PRIVATE'
g_rsa_pub_tag = 'PUBLIC'
g_rsa_reserve_size = 11


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
    # data = '{"encrypt":"参数非法", "sign":"sadsda"}'
    rsp = {}
    rsp["encrypt"] = '''jJ5O9lFxFyJgs4ZF3oVFjsGtb8l+mBZb/qXMu4di7h2ctD9i2J8XEfriF7w2RKXftf1IEPbPf6Mb
Ufx/q+XtbYgyWP0OP98B2+hcanMg4cOZF09hZMu3x9Ul/wdbezhvIMaCwM7htuQ/Y4P8o7fmAPMW
H30y/7gYFG6xh9yBVG+bhGi5UzMucNz/TS71F1/E1g7IZgH4PCURwwv+qCQGxWyYbQkaUdILTSgy
J00TJ0fheswP9XPC6zB35ppPskxYMVKQnbpTJelhMswfdlCC1IzlBMW+MI/ns8nJzv7byjbu6j2C
tX0NEf0rwc4sNZ90iNnufUSw/zJ4+n7BguN9uw=='''
    rsp["sign"] = '''UlDww+h+ZoUIsYyZ0TecXkwVXT6RIbUXWW2A2rCEL1DpCAqanYTc4NVc3S29KbfCE0jkpWsT65Mz
qH5K5LKz3eT6ruCOMiWUatAYQx9D8ji6CPGMVC4wNxu1XOQqp+qPTKhUtM9EeWuHfZwER1ujqZvd
55iji43BwaxO6ZSLh2i28YeNpXzjx2RldLQ/yJK9jby8L8u7AkTZe8vBiKfSnEr3TW26HcrEW8kI
Hd8zUqOBAo7nS9rzGUaV4kGn2M83QLq5ue9gdvpfCvAiAe0P+jVjLMIT9BaHJQxvntchbBJ0gLFG
r+Q/OJ5eF8/84/SlEscM6wjBA4DatDi2rz09pw=='''
    print(json.dumps(rsp))
    data = '参数非法'

    enc_data = pkcs8_rsa_enc(data.encode(), rsa_pub_key)
    enc_data_base64 = base64_enc(enc_data)

    show('原始数据:', data)
    show('加密编码后的结果:', enc_data_base64.decode())
    piain_data = pkcs8_rsa_dec(enc_data, rsa_pri_key)
    show('解密结果:', piain_data.decode())

    # 签名
    sig = rsa_sign(data.encode(), rsa_pri_key)
    bs64_sign = base64_enc(sig)
    show('签名结果:', bs64_sign.decode())
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
def pkcs8_rsa_sign(data, rsa_key):
    signature = ''
    try:
        h = SHA256.new(data)
        signature = PKCS1_v1_5_sign.new(rsa_key).sign(h)
    except Exception as err:
        show_exp('RSA签名失败', '', err)
    return signature


# RSA签名验证
def pkcs8_rsa_sign_verify(data, sig, rsa_key):
    try:
        h = SHA256.new(data)
        PKCS1_v1_5_sign.new(rsa_key).verify(h, sig)
        ret = True
    except (ValueError, TypeError):
        ret = False
    return ret


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
