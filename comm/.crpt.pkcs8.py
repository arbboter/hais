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
g_rsa_reserve_size = 11
g_rsa_pkcs_type = None


# 信联测试
def xl():
    dt = {"encrypt":"ebcN797ROoSVNQX6o+vIQ7mZJ81GWqCa9PJa7pB8EjwYl60vt+Ztn1xnsxsLDzxe490ap4t1R1FURkMoIoMHWh51xZEXPO4C2pvJeU7usGU7g0QOVCVIf/ttl6jLjLZ1MZNkn2UUO93biaC26Vs+6jTEidCvpwd8/+Ej3ftgzY9ppVgGM4KVSvidsXEVEiZcDxI86PztvVn1CWmBcvO6LkHzp8nRec/49cJTjKiGRfNfTxWe/3H5DoQ70JWCf4lUs+6646HWxjsWbMxwALuHSVxnxhhx9Hy3vvnmBF92zz6jA5jFny1Z+rAgHjwPJXXGi5znuUBafzws3PD5c//DzQ==","sign":"l60ZWtygP1PkhtOZqULrXm3eXei0x5ldjZQIokkVzal3HlbPNJ3E1E4TT8V0ZTR4xBVr3QkSyhndaDpA9R5NB+n5YyTC+Fj3Nxo+iSjblu8sg7qYSGkOySFKiIf61TRj16NQ3LymKNZmBO72xZL0G3A1fDyiw1VWYOcMzbNaeDOq9le2XVtPerdBGDt6nHcsCkm3U2DKzAJ/Q20LCmrfM0h4O4O/WGvSlnprMULcffjDV6sDrMmhqtd5kbJ+3WEKk3Q2pI0VeVq4YqcdJEfOk5AoKXT7rFj/GgMVkjabS2lEoWV00Y9UZ+nEuwAiyvTeVDz7ddkoyOS06diGdsl9Sw=="}
    data64 = 'GNITTvEg0Jiy0IvaTlH05UOev/mA1gwwExxlY3STCQNcgWpRSstF5BhEDnnmv5J4abBTPFGhj313aB1iVnIO1CT35+ifDc4wqZyOVDJMUoG3GSWt/fTiK8tGCAmCvl5dnSrUS6jC95PA8Z/3TwwRyxJX1YGPx7/2oo/4qK1J1xDjsX2jDzy9MImhKBOEE9jtVUyHT3ZFyItXk79EXY6GYhntRD98xK+2+ahMdVGUCO/0hZoIq95rdpqBa0N954syMudeQdQBoX6MpDaMH7nqXoLCIxbn2+XwAjCC6e2UwL7iDZqwosEj5vhyERBl5/iIyL09cFO4uLjj2wFMxcuEjg=='
    xl_private_key = "-----BEGIN RSA PUBLIC KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDiza6lqV92iEmx\nGEyFjJXiHoKlxfCl+/yyi4MD22r6mJvDscIA5FufYicASO96GB28dBDvcpigxyPs\nvBQVpwZHv0PXi896S1clnwKFxVVyl2JlzI44p3ZPE+PgZcCLsfxoclKJw7ppfVPO\ntnmRybct39L0STQJO4MjqGfGoVSP7i2hi/H7ZBrjTmAcEldJ8IHYaS8ashPy8f3C\nmWlGaqyikQ05V6VpUi4NW1BidKjSvXPXwMFwUaIGywkuh8xW3Oi12GS2R7dwIb5w\n25PKGcjtE47M7afgpFaM4xVllbAGtjfenCwpFHfFa7yx9so8jA/iRpDf6UYPSkbZ\n+TWE+lJhAgMBAAECggEAFEh6tvwHuo0Dsh/PMB5bhSZfXr3uAJohhkItzFmCHrkp\nLP4nsHa7ruxTOpZLPGsNtb3XieKAvdgxYUmMrkcKq73yLkOloXU9bPLkgdwdASuC\ntEHv8icf0ICh336aEqQvQ5P9x65GbIq1xQXSp3QXurWKoygszCqTVswHw97HtjtW\nkmtoZsIT6cLsF/A9ZF9Ao2qFQ3DANmr25JPZTvcds2wj36Uaa4e5o6CXNrOqLu1G\n7BLANE9nUGCn0x0wd0x9u2Zw/yl+3o4uBc9EuW4qp5mF5BTNFS49ZTvavW9Jlncb\nAIVLqOI5xfXyrrUhZGKGGlPdEI0dnNp3mSIYpUOzcQKBgQD/w0PRy18qsAyPqACo\nqC9Gy5d+8vmEg/f7AEDAscesfkyHKaxSMue9p1JowqY2WdG/KiYxMyhEa8WBouDM\nCF4o3zdmo1TwuuhuunvYajcgccMroHTgmsWNzuyecSzRiGfps+gdVOJ6YRuqIJiQ\nNLHWBxwv1iepp0NH7HjPMZw2BQKBgQDjA4pZqUswELbsPTG6T5xowJfT+SiywxgB\nHpAioGlQ1gvcEtvZXYugmrN5+nHaiFGzqIH11SLq6kysSgvqwHRPEKuLnB8FbZbC\nG2PFTYBgrzJFfVWQ+zWiuJRR8kSomtdkVAKgtRnk7HiUAKAiHbIFOt3heobEz3Rk\nD6C7Q8JdrQKBgH2QsQgbr2I2wkP4+DHVODiqlXr28PdVDvcEvcWcwmn2K74kAHzu\njwV2UygpgA6o9CfFGrEG65sDyhiGDZU9+nRYekuCnp39NUW/ejPamavtDiOqCBeJ\nBLpFP7fd2mIYdOOwtqFH3lS0vi89B4msxS5NmVIG8rwA6TAzcXBPa+C9AoGAJC4z\nRZj6t71iOgKCw2vexL81M355Yww+7ia92Bby0gRbPYbv7RPApichxaYJsUeapeSM\nWe7PMtuGvsrKXW6w2s0QWh7Wvtm5dlRBMXfppv8lJvgTxBiVcsqyMOFI2gpbm8zb\n4lsatmaNzSDQZL+Q2M6KAF6zzfg2V6A6AL6K4r0CgYEA7EPu0Y1BMDLoFIN+Y44G\nPJqS5ti3xSd66ukupaKp2NHjjCbfZTq2nkCzx0965jEA51bbxaAOy3CK12mtIueN\nNCYV3XSFIvAWMB8whUva4JoixXUFPnc8HWj1FO5LEb5F6P6J1E57MdaH54C5bAID\nlDm7JpsIEgsiJrfNfFQ0t9E\=\n-----END RSA PUBLIC KEY-----"
    xl_public_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4s2upalfdohJsRhMhYyV\n4h6CpcXwpfv8souDA9tq+pibw7HCAORbn2InAEjvehgdvHQQ73KYoMcj7LwUFacG\nR79D14vPektXJZ8ChcVVcpdiZcyOOKd2TxPj4GXAi7H8aHJSicO6aX1TzrZ5kcm3\nLd/S9Ek0CTuDI6hnxqFUj+4toYvx+2Qa405gHBJXSfCB2GkvGrIT8vH9wplpRmqs\nopENOVelaVIuDVtQYnSo0r1z18DBcFGiBssJLofMVtzotdhktke3cCG+cNuTyhnI\n7ROOzO2n4KRWjOMVZZWwBrY33pwsKRR3xWu8sfbKPIwP4kaQ3+lGD0pG2fk1hPpS\nYQIDAQAB\n-----END RSA PRIVATE KEY-----"
    rsa_pri_key = RSA.importKey(xl_private_key)
    rsa_pub_key = RSA.importKey(xl_public_key)
    enc_data = base64_dec(data64.encode())
    print('base64解密数据:', len(enc_data))
    plain_text = rsa_dec(enc_data, rsa_pri_key)
    print('解密后数据', plain_text)
    pass


# 测试函数
def main():
    # xl()
    # 使用pycryptodome实现RSA的加解密和签名，函数均使用pkcs1和SHA-1
    # 读取RSA公钥私钥

    # 获取密钥PEM文件路径
    key_dir = dirfile.get_user_home_dir()
    # rsa_pri_file = os.path.join(key_dir, 'rsa_private_key_2048.pem')
    # rsa_pub_file = os.path.join(key_dir, 'rsa_public_key_2048.pem')
    rsa_pri_file = os.path.join(key_dir, 'rsa_private_key.pem')
    rsa_pub_file = os.path.join(key_dir, 'rsa_public_key.pem')

    # 通过标准key文件加载rsa需要的key
    rsa_pri_key = load_rsa_file(rsa_pri_file)
    rsa_pub_key = load_rsa_file(rsa_pub_file)

    # 公钥加密，私钥解密
    # data = '{"name": "深圳新联", "type": "类型是是什么", "addr": "广东省深圳市南山区"}'
    data = '''目前主流密钥长度至少都是1024bits以上，低于1024bit的密钥已经不建议使用（安全问题）。那么上限在哪里？
    没有上限，多大都可以使用。所以，主流的模值是1024位，实际运算结果可能会略小于1024bits，注意，这个值不是绝对的，
    跟素数的生成算法有关系，只是告诉素数生成器“帮我生成一个接近1024位的素数而已”，然后生成器“好，给您一个，这
    个差不多1024位”。'''

    enc_data = rsa_enc(data.encode(), rsa_pub_key)
    enc_data_base64 = base64_enc(enc_data)

    show('原始数据:', data)
    show('加密编码后的结果:', enc_data_base64)
    plain_data = rsa_dec(enc_data, rsa_pri_key)
    show('解密结果:', plain_data)

    # 签名
    sig = rsa_sign(data.encode(), rsa_pri_key)
    show('签名结果:', sig)
    sig_ok = rsa_sign_verify(data.encode(), sig, rsa_pub_key)
    show('验证签名是否正确:', sig_ok)
    data += ' '
    sig_ok = rsa_sign_verify(data.encode(), sig, rsa_pub_key)
    show('验证签名是否正确:', sig_ok)


# 设置RSA加密类型
def set_rsa_pkcs_type(tp):
    global g_rsa_pkcs_type

    if tp == 'pkcs1':
        g_rsa_pkcs_type = PKCS1_OAEP
    elif tp == 'pkcs8':
        g_rsa_pkcs_type = PKCS1_v1_5
    else:
        g_rsa_pkcs_type = tp
    return g_rsa_pkcs_type


# 返回当前的pkcs类型
def get_pkcs(rsa_key):
    if g_rsa_pkcs_type:
        return g_rsa_pkcs_type
    try:
        pkcs_type = PKCS1_OAEP
        key_size = rsa_key.size_in_bits()
        if key_size > 1024 :
            pkcs_type = PKCS1_v1_5
    except Exception as err:
        show_exp('获取RSA类型失败', rsa_key, err)
    return pkcs_type


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

    print('block size:', bs)
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
        cipher = get_pkcs(rsa_key).new(rsa_key)
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
        cipher = get_pkcs(rsa_key).new(rsa_key)
        for dat in block_data(data, rsa_key):
            if len(dat) > 117:
                cur_text = cipher.decrypt(dat, "rsa dec failed")
            else:
                cur_text = cipher.decrypt(dat)
            plaintext += cur_text
        plaintext = plaintext.decode()
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
def rsa_key_str2std(skey):
    ret = None
    try:
        ret = RSA.importKey(skey)
    except Exception as err:
        show_exp('字符串密钥转rsa格式密钥错误', skey, err)
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
