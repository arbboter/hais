# -*- coding: utf-8 -*-
from pyhias import db
from comm import db_util
from pyhias import co_xl as mypro


# 主程序
def main():
    # 数据库初始化
    db.set_db(db_util.CDBSqlite, './data/hias.db')

    # 添加测试用例
    # mypro.add_new_case()

    # 根据id执行测试用例
    mypro.run_case_by_apiids(['6654'])
    return

    # 根据api_id执行测试用例
    # mypro.run_case_by_apiids(['5405'])

    # 根据用户id执行
    mypro.run_case_by_userid('1001')


if __name__ == '__main__':
    main()
