# -*- coding: utf-8 -*-

# coding:utf-8
import urllib.request
import urllib.parse

g_headers = {
    'User-Agent': 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'
}

g_proxy = {'http': 'http://127.0.0.1:8086/',
           'https': 'http://127.0.0.1:8086/'}


# 测试主程序
def main():
    # install_proxy()
    rsp = http_get('https://blog.csdn.net/mtbaby')
    print(rsp)


# 设置代理地址
def set_proxy(xy):
    global g_proxy
    g_proxy = xy


# 添加代理
def add_proxy(k, v):
    global g_proxy
    g_proxy[k] = v


# 安装代理
def install_proxy(proxy = g_proxy):
    proxy_handler = urllib.request.ProxyHandler(proxy)
    http_opener = urllib.request.build_opener(proxy_handler)
    urllib.request.install_opener(http_opener)
    return http_opener


# 设置头
def set_headers(hd):
    global g_headers
    g_headers = hd


# 追加头
def add_headers(k, v):
    global g_headers
    g_headers[k] = v


def make_http_get_url(http_url, para):
    if len(para) == 0:
        return http_url

    url_rsp = ''
    try:
        paras = []
        for k in para:
            paras.append(k + '=' + str(para[k]))

        rsp = '&'.join(paras)
        url_rsp += http_url + '?' + rsp
    except Exception as err:
        url_rsp = http_url
        print(err)
    return url_rsp


def http_get(http_url, heads=g_headers, encoding='utf-8'):
    try:
        http_req = urllib.request.Request(url=http_url, headers=heads)
        req = urllib.request.urlopen(http_req)
        rsp = req.read().decode(encoding)
    except Exception as err:
        rsp = str(err)
    return rsp


def http_post(http_url, data, heads=g_headers, encoding='utf-8'):
    try:
        http_data = urllib.parse.urlencode(data).encode(encoding)
        req = urllib.request.Request(http_url, http_data, heads)
        rsp = urllib.request.urlopen(req).read().decode(encoding)
    except Exception as err:
        rsp = str(err)
    return rsp


if __name__ == '__main__':
    main()
