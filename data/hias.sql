CREATE TABLE t_interface
(
id              INTEGER PRIMARY KEY,                -- 接口id
name            VARCHAR(128) NOT NULL DEFAULT '',   -- 接口名称
para            VARCHAR(512) NOT NULL DEFAULT '{}', -- 接口参数
ret             VARCHAR(512) NOT NULL DEFAULT '',   -- 接口返回值，填类型或者示例
batch_id        INTEGER NOT NULL DEFAULT 0,         -- 批次id
user_id         INTEGER NOT NULL DEFAULT 0,         -- 用户id
create_time     TimeStamp NOT NULL DEFAULT CURRENT_TIMESTAMP, -- 创建时间
update_time     TimeStamp NOT NULL DEFAULT CURRENT_TIMESTAMP -- 更新时间
);

CREATE TABLE t_test_case
(
id              INTEGER PRIMARY KEY, -- 测试用例id
name            VARCHAR(128) NOT NULL DEFAULT '', -- 测试用例名称
api_id          INTEGER NOT NULL DEFAULT 0, -- 接口id
addr            VARCHAR(512) NOT NULL DEFAULT '', -- 接口地址，如URL
protocol        VARCHAR(16) NOT NULL DEFAULT 'http', -- 协议类型
method          VARCHAR(16) NOT NULL DEFAULT 'get', -- 请求方法
header          VARCHAR(512) NOT NULL DEFAULT '{}', -- 请求头
req_envi        VARCHAR(512) NOT NULL DEFAULT '{}', -- 环境变量
para            VARCHAR(512) NOT NULL DEFAULT '{}', -- 测试用例参数
rsp_check       VARCHAR(512) NOT NULL DEFAULT '{}', -- 返回值校验信息
user_id         INTEGER NOT NULL DEFAULT 0, -- 用户id
create_time     TimeStamp NOT NULL DEFAULT CURRENT_TIMESTAMP, -- 创建时间
update_time     TimeStamp NOT NULL DEFAULT CURRENT_TIMESTAMP -- 更新时间
);

-- t_test_case_rsp -- 测试用例执行结果表
CREATE TABLE t_test_case_rsp
(
id              INTEGER PRIMARY KEY, -- 测试用例结果id
name            VARCHAR(128) NOT NULL DEFAULT '', -- 测试用例结果名称
case_id         VARCHAR(128) NOT NULL DEFAULT '', -- 测试用例id
req             VARCHAR(512) NOT NULL DEFAULT '', -- 接口请求
rsp             TEXT NOT NULL DEFAULT '', -- 接口返回
ret_code        INTEGER NOT NULL DEFAULT 0, -- 返回码
ret_msg         VARCHAR(128) NOT NULL DEFAULT '', -- 返回信息
rsp_check       VARCHAR(512) NOT NULL DEFAULT '{}', -- 返回值校验信息
user_id         INTEGER NOT NULL DEFAULT 0, -- 用户id
beg_time        INTEGER NOT NULL DEFAULT 0, -- 执行开始时间
end_time        INTEGER NOT NULL DEFAULT 0, -- 执行结束时间
create_time     TimeStamp NOT NULL DEFAULT CURRENT_TIMESTAMP, -- 创建时间
update_time     TimeStamp NOT NULL DEFAULT CURRENT_TIMESTAMP -- 更新时间
);

-- http接口参数
CREATE TABLE t_http_para
(
id              INTEGER PRIMARY KEY, -- 参数id
name            VARCHAR(128) NOT NULL DEFAULT '', -- 参数名称
protocol        VARCHAR(8) NOT NULL DEFAULT 'http', -- 协议类型
header          VARCHAR(512) NOT NULL DEFAULT '{}', -- 请求头
para            VARCHAR(1024) NOT NULL DEFAULT '{}', -- 请求数据
rsp_check       VARCHAR(1024) NOT NULL DEFAULT '{}', -- 结果数据检查
user_id         INTEGER NOT NULL DEFAULT 0, -- 用户id
create_time     TimeStamp NOT NULL DEFAULT CURRENT_TIMESTAMP, -- 创建时间
update_time     TimeStamp NOT NULL DEFAULT CURRENT_TIMESTAMP -- 更新时间
);
