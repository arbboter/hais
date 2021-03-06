# -*- coding: utf-8 -*-
from comm import crpt
from conf import hias as hias_conf
import base64

g_my_rsa_private_key = crpt.load_rsa_file(hias_conf.g_app['my_rsa_private_key'])
g_my_rsa_public_key = crpt.load_rsa_file(hias_conf.g_app['my_rsa_public_key'])
g_ser_rsa_private_key = crpt.load_rsa_file(hias_conf.g_app['ser_rsa_private_key'])
g_ser_rsa_public_key = crpt.load_rsa_file(hias_conf.g_app['ser_rsa_public_key'])


# 加密
def rsa_enc(data):
    # 长度太长则分块加密
    enc_data = crpt.pkcs8_rsa_enc(data, g_ser_rsa_public_key)
    return base64.encodestring(enc_data)


# 解密
def rsa_dec(data):
    data = base64.decodestring(data)
    return crpt.pkcs8_rsa_dec(data, g_my_rsa_private_key)


# 签名
def rsa_sign(data):
    sign_data = crpt.pkcs8_rsa_sign(data, g_my_rsa_private_key)
    return base64.encodestring(sign_data)


# 验证签名
def rsa_sign_verify(data, sig):
    sig = base64.decodestring(sig)
    return crpt.pkcs8_rsa_sign_verify(data, sig, g_ser_rsa_public_key)


def main():
    pass


if __name__ == '__main__':
    main()
