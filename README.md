# probe
一个纯 Go 语言编写的全平台 NAT 类型探测工具

# 快速安装
```shell
go install github.com/xiaoqidun/probe@latest
```

# 手动安装
1. 根据系统架构下载为你编译好的[二进制文件](https://aite.xyz/product/probe/)
2. 将下载好的二进制文件重命名为 probe 并保留后缀
3. 把 probe 文件移动到系统 PATH 环境变量中的目录下
4. windows 外的系统需使用 chmod 命令赋予可执行权限

# 典型场景
```shell
# 基础用法 (自动选择协议)
probe

# 强制使用 IPv4 协议
probe -ip 4

# 强制使用 IPv6 协议
probe -ip 6

# 使用代理（SOCKS5 UDP协议）
probe -s5 127.0.0.1:54321

# 使用自定义服务器（STUN协议）
probe -s1 stun.miwifi.com:3478
```

# 授权协议
本项目使用 [Apache License 2.0](https://github.com/xiaoqidun/probe/blob/main/LICENSE) 授权协议