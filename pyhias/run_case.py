# -*- coding: utf-8 -*-
from comm import http_util
from comm import slog
from comm import stime
from comm import util
import json


def main():
    pass


# 运行测试用例
def run_test_case(req_dd):
    try:
        ret_ok = True
        case_rsp = {'req': '', 'rsp': '', 'beg_time': '', 'ret_msg': '执行成功',
                    'end_time': '', 'update_time': stime.timestamp()}
        # url
        http_url = req_dd['addr'].strip()

        # 请求类型
        http_method = req_dd['method'].upper()

        # 请求头
        headers = http_util.g_headers
        if 'header' in req_dd and not util.is_json_null(req_dd['header']):
            headers = req_dd['header']

        # 参数请求
        http_para = req_dd['para']
        http_para = json.loads(http_para)
        beg_time = stime.timestamp()
        if http_method == 'GET':
            http_url = http_util.make_http_get_url(http_url, http_para)
            rsp = http_util.http_get(http_url, headers)
        else:
            rsp = http_util.http_post(http_url, http_para, headers)
        end_time = stime.timestamp()

        # 返回结果处理
        case_rsp = {'req': http_url, 'rsp': rsp, 'beg_time': beg_time, 'ret_msg': '执行成功',
                    'end_time': end_time, 'update_time': stime.timestamp()}
    except Exception as err:
        ret_ok = False
        case_rsp['req'] = http_url
        case_rsp['ret_msg'] = '执行异常:' + str(err)
        slog.show_exp('测试用例运行出错', req_dd, err)
    return ret_ok, case_rsp


if __name__ == '__main__':
    main()
