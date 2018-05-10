# -*- coding: utf-8 -*-
from comm import crpt
from comm import slog
from comm import stime
from comm import util
from pyhias import crypto as hias_crypto
from pyhias import run_case
from pyhias import db
import copy
import json


def main():
    pass


# 添加测试用例
def add_new_case():
    dd = {}
    dd.update({'user_id': 1001, 'create_time': stime.timestamp(), 'update_time': stime.timestamp(),
               'method': 'POST', 'protocol': 'https'})
    dd_in = {'name': '接口名字', 'api_id': '接口id号', 'addr': '接口调用地址或名称', 'para': '接口参数,json格式'}

    # 获取用户输入
    user_input = util.get_input(dd_in)
    dd.update(user_input)

    db.dd_insert('t_test_case', dd)
    return dd


# 根据SQL字段条件运行测试用例
def run_case_by_db(dd_conn):
    # 获取测试用例数据
    case_datas = db.dd_query('t_test_case', dd_conn)
    if not case_datas:
        # slog.show('未找到符合条件的测试用例')
        return True

    case_data = case_datas
    for c in case_data:
        show_para = ['id', 'addr', 'para']
        par = ''
        for p in show_para:
            par += p + '[' + str(c[p]) + '] '
        slog.show('请求:', par)
        try:
            dd = run_api_case(c)
            if dd:
                # 结果写入数据库
                db.dd_insert('t_test_case_rsp', dd)
                slog.show('结果', dd['ret_msg'], ' -> 测试结果已写入数据库')
        except Exception as err:
            slog.show_exp('执行测试用例失败', par, err)


# 根据批次运行测试用例
def run_case_by_batchid(batch_id):
    pass


# 根据用例内部id运行测试用例
def run_case_by_ids(ids=[]):
    for i in ids:
        dd = {'id': i}
        run_case_by_db(dd)


# 根据用户id运行测试用例
def run_case_by_userid(user_id):
    dd = {'user_id': user_id}
    run_case_by_db(dd)


# 根据api_id运行测试用例
def run_case_by_apiids(ids=[]):
    for i in ids:
        dd = {'api_id': i}
        run_case_by_db(dd)


def run_api_case(case_data):
    try:
        case_info = {}
        # 入参检查
        need_para = ['para', 'addr', 'id', 'method', 'user_id']
        for i in need_para:
            if i not in case_data:
                raise RuntimeError('缺少入参['+i+'], 请检查')

        case_info.update({'case_id': case_data['id'], 'user_id': case_data['user_id']})
        # 针对接口请求前参数加密签名处理
        # 请求参数加密签名预处理
        para = case_data['para']
        ret_ok, req_para = http_req_para_predeal(para)
        if not ret_ok:
            raise RuntimeError('参数预处理出错，请检查参数:'+para)

        # 需要对请求参数预处理，然后替换预处理后的请求参数
        xldd = copy.deepcopy(case_data)
        xldd['para'] = req_para
        # print(req_para)

        # 执行测试用例
        ret_ok, case_rsp = run_case.run_test_case(xldd)
        if not ret_ok:
            raise RuntimeError('测试用例执行失败:' + case_rsp['ret_msg'])

        # 请求结果解密,验证
        rsp = case_rsp['rsp']
        # 判断结果是否为合法json格式
        if not util.is_json(rsp):
            case_rsp['ret_code'] = '1001'
            case_rsp['ret_msg'] = '数据结果非法，非合法json格式'
        else:
            ret_ok, text = http_rsp_para_predeal(rsp)
            case_rsp['rsp'] = text
            if ret_ok:
                case_rsp['ret_code'] = '0000'
                case_rsp['ret_msg'] = '接收应答成功'
            else:
                case_rsp['ret_code'] = '1001'
                case_rsp['ret_msg'] = '数据结果非法，解密验签失败'
        case_info.update(case_rsp)
    except Exception as err:
        slog.show_exp('接口测试不通过', req_para, err)
        if 'ret_msg' not in case_info:
            case_info['ret_code'] = '1000'
            case_info['ret_msg'] = '接口测试不通过' + str(err)
    return case_info


# xl请求参数加密签名
def http_req_para_predeal(para):
    try:
        ret_ok = True
        deal_data = {}
        ret_para = {}

        # 入参要求是json格式
        if not util.is_json(para):
            raise RuntimeError('请求参数非法，为非合法json格式')

        # 读取请求参数并转成字典
        para_dd = json.loads(para)

        # 流水号字段
        lshTag = 'reqSerialNo'
        if lshTag in para_dd:
            para_dd[lshTag] = stime.get_id()

        # 选出需要处理的数据
        for k, v in para_dd.items():
            # 忽略不需要加密的直接
            if k in ['insId', 'operId']:
                ret_para[k] = v
            else:
                deal_data[k] = v

        # 加密处理的数据
        jpara = json.dumps(deal_data).encode()
        enc_para = hias_crypto.rsa_enc(jpara)
        ret_para['encrypt'] = enc_para.decode()
        # print('enc:', ret_para['encrypt'])

        # 数据签名
        sign = hias_crypto.rsa_sign(jpara)
        ret_para['sign'] = sign.decode()
        # print('sign:', ret_para['sign'])

        json_para = json.dumps(ret_para)
    except Exception as err:
        slog.show_exp('参数加密签名出错', para, err)
        json_para = '{}'
        ret_ok = True
    return ret_ok, json_para


# xl返回参数解密密验证签名
def http_rsp_para_predeal(rsp_data):
    try:
        plian_txt = rsp_data
        sign_ok = False

        # 解密处理的数据
        para_dd = json.loads(rsp_data)
        enc_data = para_dd['encrypt'].encode()
        para_dd['plain_text'] = hias_crypto.rsa_dec(enc_data).decode()
        plian_txt = json.dumps(para_dd)

        # 数据签名
        sign_data = para_dd['sign'].encode()
        sign_ok = hias_crypto.rsa_sign_verify(para_dd['plain_text'].encode(), sign_data)
        print('请求结果:', para_dd['plain_text'])
    except Exception as err:
        slog.show_exp('返回参数解密密验证签名失败', '', err)
    return sign_ok, plian_txt


if __name__ == '__main__':
    main()
