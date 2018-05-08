# -*- coding: utf-8 -*-
import sys
from comm import stime
import os
import threading


g_log_dir = '../log'
g_log_name = 'app'
g_log_lv = 0

g_log_lv_debug = 0
g_log_lv_info = 1
g_log_lv_warn = 2
g_log_lv_error = 3
g_log_lv_fatal = 4


# 测试主程序
def main():
    logd('瓜娃子', 'hhhdha')
    logi('瓜娃子', 'hhhdha')
    logw('瓜娃子', 'hhhdha')
    loge('瓜娃子', 'hhhdha')
    logf('瓜娃子', 'hhhdha')


# 打印信息
def show(*arg):
    print(*arg)


# 显示异常信息
def show_exp(msg, para, err):
    frame = sys._getframe(1)
    func_info = func_call_info(frame)
    print(func_info + '执行异常:' + str(msg) + '[' + str(err) + '] -> '+str(para))


# 获取日志等级
def get_log_lv(lv_name):
    log_lv_dd = {'debug': g_log_lv_debug, 'info': g_log_lv_info, 'warn': g_log_lv_warn,
                 'error': g_log_lv_error, 'fatal': g_log_lv_fatal}

    # 等级
    lv = 0
    name = lv_name
    if lv_name in log_lv_dd:
        lv = log_lv_dd[lv_name]
        name = lv_name
    return lv, name


# 设置日志参数
def set_log(log_dir='../log', name='', lv_name='debug'):
    global g_log_dir
    global g_log_name
    global g_log_lv

    g_log_dir = log_dir[:]
    g_log_lv, _ = get_log_lv(lv_name)
    g_log_name = name

    # 创建目录
    if not os.path.exists(g_log_dir):
        os.makedirs(g_log_dir)


# 显示断点
def tag(info=' @@ YOU HAVE TAG HERE @@'):
    # 获取上层调用堆栈信息
    frame = sys._getframe(1)

    # 调用信息
    log_str = func_call_info(frame)
    log_str += info
    show(log_str)


# 函数调用信息
def func_call_info(func_frame):
    # 调用信息
    code = func_frame.f_code
    tm = stime.timestamp()
    file_name = os.path.basename(code.co_filename)
    file_line = code.co_firstlineno
    file_func = code.co_name
    tid = threading.current_thread().ident
    pid = os.getpid()
    log_str = '[%s] [%s,%s,%s] [%s,%s] ' % (tm, file_name, file_line, file_func, pid, tid)
    return log_str


# 日志
def log(txt, fn='../log/buf.log', dp=1):
    # 创建目录
    if not os.path.exists(g_log_dir):
        os.makedirs(g_log_dir)

    # 获取上层调用堆栈信息
    frame = sys._getframe(dp)

    # 调用信息
    code = frame.f_code
    tm = stime.timestamp()
    file_name = os.path.basename(code.co_filename)
    file_line = code.co_firstlineno
    file_func = code.co_name
    tid = threading.current_thread().ident
    pid = os.getpid()

    # 日志信息
    log_str = '[%s] [%s,%s,%s] [%s,%s] ' % (tm, file_name, file_line, file_func, pid, tid)
    log_str += txt

    # 写文件
    with open(fn, 'a+', encoding='utf-8', errors='ignore') as fd:
        fd.write(log_str)
        fd.write('\n')


# 等级日志
def log_lvname(lvname, *txt):
    lv, tag = get_log_lv(lvname)
    if lv < g_log_lv:
        return

    log_file = g_log_name + '_' + stime.get_cur_date() + '.log'
    log_file = os.path.join(g_log_dir, log_file)
    log_txt = '# %s #' % (tag) + ', '.join([str(v) for v in txt])
    log(log_txt, log_file, dp=3)


# 对外打印日志
def logd(*txt):
    log_lvname('debug', *txt)


def logi(*txt):
    log_lvname('info', *txt)


def logw(*txt):
    log_lvname('warn', *txt)


def loge(*txt):
    log_lvname('error', *txt)


def logf(*txt):
    log_lvname('fatal', *txt)


if __name__ == '__main__':
    main()
