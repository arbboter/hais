# -*- coding: utf-8 -*-
import time


# 当前模块主程序
def main():
    print(timestamp())


class CTimeCount:
    def __int__(self):
        self.beg = time.time()
        self.end = self.beg
        self.cost = 0

    def cost_time(self):
        return self.cost

    def beg_time(self):
        return timestamp(self.beg)

    def end_time(self):
        return timestamp(self.end)

    def start(self):
        self.beg = time.time()
        self.end = self._beg
        self.cost = 0

    def stop(self):
        self.end = time.time()
        self.cost += self.end - self.beg
        return self.cost

    def pause(self):
        self.end = time.time()
        self.cost += self.end - self.beg
        return self.cost

    def resume(self):
        self.beg = time.time()
        self.end = self.beg
        return self.cost

    # 获取日期
def get_date(local_time, dim=''):
    date_time = time.strftime('%Y-%m-%d', local_time)
    return dim.join(date_time.split('-'))


# 获取当前日期
def get_cur_date(dim=''):
    local_time = time.localtime()
    return get_date(local_time, dim)


# 获取时间
def get_time(local_time, dim=''):
    date_time = time.strftime('%H:%M:%S', local_time)
    return dim.join(date_time.split(':'))


# 获取当前时间
def get_cur_time(dim=''):
    local_time = time.localtime()
    return get_time(local_time, dim)


# 时间戳
def timestamp(tm=0):
    cur_time = tm
    if tm == 0:
        cur_time = time.time()
    ltm = time.localtime(cur_time)
    date_time = time.strftime('%Y-%m-%d %H:%M:%S', ltm)
    date_secs = str(cur_time).split('.')[-1]
    return date_time + '.' + date_secs


if __name__ == '__main__':
    main()
