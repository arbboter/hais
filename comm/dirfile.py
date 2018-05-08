# -*- coding: utf-8 -*-
import os


# 测试函数
def main():
    rst = get_user_home_dir()
    print(rst)


# 用户主目录
def get_user_home_dir():
    return os.path.expanduser('~')


# main模块
if __name__ == '__main__':
    main()
