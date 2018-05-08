# -*- coding: utf-8 -*-
from comm import slog
import sqlite3


def main():
    pass


# SQL数据格式
def sql_value(v):
    vt = type(v)
    if vt in [str]:
        return "'" + v.replace("'", '"') + "'"
    else:
        return str(v)


# 数据插入,根据字典项插入
def db_insert(db_conn, tab_name, dd_item):
    try:
        ret = True
        # 组装SQL
        sql = 'insert into ' + tab_name + '('
        sql_names = ', '.join([v for v in dd_item.keys()])
        sql += sql_names + ') values('
        sql += ', '.join([sql_value(v) for v in dd_item.values()])
        sql += ')'
        # 执行SQL
        db_conn.exec(sql)
    except Exception as err:
        slog.show_exp('执行SQL插入语句失败', sql, err)
        ret = False
    return ret


# 数据插入,根据字典项插入
def db_query(db_conn, tab_name, dd_cond, cols):
    try:
        ret = []
        # 组装SQL
        sql = 'select ' + ','.join(cols) + ' from ' + tab_name
        if dd_cond:
            kvs = []
            for k, v in dd_cond.items():
                kvs.append(str(k) + '=' + sql_value(v))
            sql += ' where ' + ' and '.join(kvs)
        # 执行SQL
        rows = db_conn.query(sql)
        for r in rows:
            cur = {}
            for i, v in enumerate(r):
                cur[cols[i]] = v
            ret.append(cur)
    except Exception as err:
        slog.show_exp('执行SQL查询语句失败', sql, err)
    return ret


# sqlite数据库连接类
class CDBSqlite:
    def __init__(self, dbi):
        self.file = dbi

    def exec(self, sql):
        try:
            conn = sqlite3.connect(self.file)
            c = conn.cursor()
            c.execute(sql)
            conn.commit()
            conn.close()
            ret = True
        except Exception as err:
            slog.show_exp('SQL执行出错', sql, err)
            ret = False
        return ret

    def query(self, sql):
        try:
            rows = []
            conn = sqlite3.connect(self.file)
            c = conn.cursor()
            cur = c.execute(sql)
            for r in cur:
                rows.append(r)
            conn.close()
        except Exception as err:
            slog.show_exp('SQL执行出错', sql, err)
        return rows


if __name__ == '__main__':
    main()
