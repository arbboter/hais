# -*- coding: utf-8 -*-
import json

def main():
    pass


def to_encode(data, encoding='utf-8'):
    if type(data) == str:
        return data.encode(encoding)
    return data


# 判断是否为json字符串
def is_json(s):
    try:
        json.loads(s, strict=False)
        return True
    except Exception as err:
        # print(err, '->', s)
        return False


# 判断是否为json字符串是否为空
def is_json_null(s):
    try:
        js = s.strip()
        if len(js) == 0:
            return True

        jd = json.loads(s)
        if len(jd) > 0:
            return False
        else:
            return True
    except:
        return False

# 获取用户输入，提供输入字典
def get_input(dd):
    ret = {}
    for d in dd:
        ui = input('please input [' + d + '], ' + dd[d] + ':')
        if ui:
            ret[d] = ui
    return ret


if __name__ == '__main__':
    main()
