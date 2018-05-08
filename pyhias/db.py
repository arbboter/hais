# -*- coding: utf-8 -*-
from comm import db_util
from comm import slog
from comm import test_data
import json
import random

# 设定数据库类
g_db_conn = None

dd_col_name = {'t_interface': ['id', 'name', 'para', 'ret', 'batch_id', 'user_id', 'create_time', 'update_time'],
               't_test_case': ['id', 'name', 'api_id', 'addr', 'protocol', 'method', 'header', 'req_envi', 'para',
                               'rsp_check', 'user_id', 'create_time', 'update_time'],
               't_test_case_rsp': ['id', 'name', 'case_id', 'req', 'rsp', 'ret_code', 'ret_msg', 'rsp_check', 'user_id',
                                   'beg_time', 'end_time', 'create_time', 'update_time'],
               't_http_para': ['id', 'name', 'protocol', 'header', 'para', 'rsp_check', 'user_id', 'create_time', 'update_time']
               }


# 设置数据库对象
def set_db(db_type, dbi):
    global g_db_conn
    g_db_conn = db_type(dbi)


# 写入数据
def dd_insert(tb, dd):
    return db_util.db_insert(g_db_conn, tb, dd)


# 数据查询
def dd_query(tb, dd_cond):
    if tb in dd_col_name:
        return db_util.db_query(g_db_conn, tb, dd_cond, dd_col_name[tb])
    else:
        slog.show_exp('数据查询失败', tb, '表配置不存在')


# 获取接口测试数据
def get_test_case(dd):
    items = []
    for k, v in dd.items():
        items.append(k + '=' + db_util.sql_value(v))
    t_name = 't_test_case'
    sql = 'select * from ' + t_name
    if items:
        sql += ' where ' + ' and '.join(items)
    return g_db_conn.query(sql)


# 添加测试数据
def add_test_data(tb_name):
    r = test_data.CRandData()
    para = {}
    para_num = random.randint(2, 5)
    for n in range(para_num):
        para[r.en_word()] = r.en_sequ()

    kv = []
    for k, v in para.items():
        kv.append(k+'='+v)
    skv = '&'.join(kv)

    all_data = {}
    json_para = json.dumps(para)
    all_data['t_interface'] = {'name': r.en_sequ(), 'para': json_para, 'ret': '返回值', 'batch_id': random.randint(1, 20),
                               'user_id': random.randint(1001, 1006)}
    all_data['t_test_case'] = {'name': r.en_sequ(), 'api_id': r.id(), 'addr': r.url(), 'protocol': 'http', 'para': json_para,
                               'method': 'get', 'user_id': random.randint(1001, 1006)}
    all_data['t_test_case_rsp'] = {'name': r.en_sequ(), 'case_id': r.id(), 'req': r.url()+'?'+skv,
                                   'rsp_check': '{"ret_code":0}', 'user_id': random.randint(1001, 1006)}
    all_data['t_http_para'] = {'name': r.en_sequ(), 'protocol': 'http', 'para': json_para,
                               'rsp_check': '{"ret_code":0}', 'user_id': random.randint(1001, 1006)}
    if tb_name in all_data:
        return db_util.db_insert(g_db_conn, tb_name, all_data[tb_name])
    else:
        slog.show('表'+tb_name+'配置不存在')


def main():
    tb_name = ['t_interface', 't_test_case', 't_test_case_rsp', 't_http_para']
    # add_test_data(tb_name[3])
    dd = {'id': 35}
    print(get_test_case(dd))


if __name__ == '__main__':
    main()
