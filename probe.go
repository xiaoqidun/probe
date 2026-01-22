// Copyright 2026 肖其顿 (XIAO QI DUN)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"fmt"
	"net"
	"strings"
	"time"
)

func main() {
	var (
		ip string
		s1 string
		s2 string
		s5 string
		to time.Duration
	)
	flag.StringVar(&ip, "ip", "", "协议版本")
	flag.StringVar(&s1, "s1", "stun.l.google.com:19302", "主服务器")
	flag.StringVar(&s2, "s2", "", "次服务器")
	flag.StringVar(&s5, "s5", "", "代理地址")
	flag.DurationVar(&to, "to", 10*time.Second, "超时时间")
	flag.Parse()
	network := "udp"
	switch ip {
	case "":
		network = "udp"
	case "4":
		network = "udp4"
	case "6":
		network = "udp6"
	default:
		flag.PrintDefaults()
		return
	}
	var conn net.PacketConn
	var err error
	if s5 != "" {
		fmt.Printf("通过代理探测: %s\n", s5)
		conn, err = DialSocks5UDP(s5, network)
		if err != nil {
			fmt.Printf("连接代理失败: %v\n", err)
			return
		}
	} else {
		fmt.Printf("本地直接探测: %s\n", network)
		conn, err = net.ListenPacket(network, ":0")
		if err != nil {
			fmt.Printf("本地监听失败: %v\n", err)
			return
		}
	}
	defer conn.Close()
	if s5 == "" {
		fmt.Printf("本地监听地址: %s\n", conn.LocalAddr())
	}
	s1p := fmt.Sprintf("探测服务器一: %s (%s)", s1, network)
	fmt.Println(s1p)
	maxW := displayWidth(s1p)
	if s2 != "" {
		s2p := fmt.Sprintf("探测服务器二: %s (%s)", s2, network)
		fmt.Println(s2p)
		if w2 := displayWidth(s2p); w2 > maxW {
			maxW = w2
		}
	}
	fmt.Println(strings.Repeat("-", maxW))
	result := DetectNAT(conn, s1, s2, network, to)
	fmt.Printf("NAT 类型结果: %s\n", result.Type)
	if result.MappedIP != "" {
		fmt.Printf("本地映射地址: %s\n", result.MappedIP)
	}
	fmt.Printf("映射行为模式: %s\n", result.Mapping)
	fmt.Printf("过滤行为模式: %s\n", result.Filtering)
}
