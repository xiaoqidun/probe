# probe
一个高性能、零依赖的纯 Go 语言 NAT 类型探测

# 快速安装
```shell
go install github.com/xiaoqidun/probe@latest
```

# 典型场景
```shell
# 基础用法 (自动选择协议)
probe

# 强制使用 IPv4 协议
probe -ip 4

# 强制使用 IPv6 协议
probe -ip 6

# 使用代理（仅限SOCKS5 UDP协议）
probe -s5 127.0.0.1:54321
```

# 授权协议
本项目使用 [Apache License 2.0](https://github.com/xiaoqidun/probe/blob/main/LICENSE) 授权协议