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
	"crypto/rand"
	"net"
	"strconv"
	"time"
)

// MappingEndpointIndependent 独立映射模式常量
const MappingEndpointIndependent = "Endpoint-Independent"

// MappingAddressDependent 地址相关映射模式常量
const MappingAddressDependent = "Address-Dependent"

// MappingAddressPortDependent 地址端口相关映射模式常量
const MappingAddressPortDependent = "Address and Port-Dependent"

// MappingUnknown 未知映射模式常量
const MappingUnknown = "Unknown"

// FilteringEndpointIndependent 独立过滤模式常量
const FilteringEndpointIndependent = "Endpoint-Independent"

// FilteringAddressDependent 地址相关过滤模式常量
const FilteringAddressDependent = "Address-Dependent"

// FilteringAddressPortDependent 地址端口相关过滤模式常量
const FilteringAddressPortDependent = "Address and Port-Dependent"

// FilteringUnknown 未知过滤模式常量
const FilteringUnknown = "Unknown"

// NATOpen 公网类型常量
const NATOpen = "Open Internet"

// NATFullCone 全锥型NAT常量
const NATFullCone = "Full Cone"

// NATRestricted 限制锥型NAT常量
const NATRestricted = "Restricted Cone"

// NATPortRestricted 端口限制锥型NAT常量
const NATPortRestricted = "Port Restricted Cone"

// NATSymmetric 对称型NAT常量
const NATSymmetric = "Symmetric"

// NATUDPBlocked UDP阻塞常量
const NATUDPBlocked = "UDP Blocked"

// NATUnknown 未知类型常量
const NATUnknown = "Unknown"

// NATResult NAT探测结果结构
type NATResult struct {
	Type      string
	Mapping   string
	Filtering string
	MappedIP  string
}

// resolveAddr 解析探测目标地址
// 入参: conn 当前连接, addrStr 目标地址字符串, network 网络协议
// 返回: addr 解析后的网络地址, err 解析错误
func resolveAddr(conn net.PacketConn, addrStr, network string) (net.Addr, error) {
	host, portStr, err := net.SplitHostPort(addrStr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	if _, ok := conn.(*socks5PacketConn); ok {
		if net.ParseIP(host) == nil && host != "localhost" && host != "127.0.0.1" {
			return &SocksAddr{Host: host, Port: port}, nil
		}
	}
	return net.ResolveUDPAddr(network, addrStr)
}

// performTest 执行单次STUN探测
// 入参: conn 连接对象, serverAddr STUN服务器地址, network 协议, timeout 超时设定, changeIP 变更IP标志, changePort 变更端口标志
// 返回: msg 响应消息, addr 响应源地址, err 探测错误
func performTest(conn net.PacketConn, serverAddr string, network string, timeout time.Duration, changeIP, changePort bool) (*stunMessage, *net.UDPAddr, error) {
	dst, err := resolveAddr(conn, serverAddr, network)
	if err != nil {
		return nil, nil, err
	}
	txID := [12]byte{}
	if _, err := rand.Read(txID[:]); err != nil {
		return nil, nil, err
	}
	req := encodeSTUNRequest(txID, changeIP, changePort)
	if _, err := conn.WriteTo(req, dst); err != nil {
		return nil, nil, err
	}
	conn.SetReadDeadline(time.Now().Add(timeout))
	defer conn.SetReadDeadline(time.Time{})
	buf := make([]byte, 2048)
	for i := 0; i < 3; i++ {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				break
			}
			return nil, nil, err
		}
		msg, err := decodeSTUNResponse(buf[:n], txID)
		if err != nil {
			continue
		}
		uAddr, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		return msg, uAddr, nil
	}
	return nil, nil, nil
}

// DetectNAT 执行NAT类型检测核心逻辑
// 入参: conn 连接对象, primarySTUN 主服务器, secondarySTUN 辅服务器, network 协议, timeout 超时设定
// 返回: result 检测结果
func DetectNAT(conn net.PacketConn, primarySTUN, secondarySTUN, network string, timeout time.Duration) NATResult {
	res := NATResult{Type: NATUnknown, Mapping: MappingUnknown, Filtering: FilteringUnknown}
	resp1, _, err := performTest(conn, primarySTUN, network, timeout, false, false)
	if err != nil || resp1 == nil {
		res.Type = NATUDPBlocked
		return res
	}
	mappedAddr1 := resp1.GetMappedAddress()
	if mappedAddr1 == nil {
		return res
	}
	res.MappedIP = mappedAddr1.String()
	if localAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		if localAddr.IP.Equal(mappedAddr1.IP) && localAddr.Port == mappedAddr1.Port {
			res.Type = NATOpen
			res.Mapping = MappingEndpointIndependent
			res.Filtering = FilteringEndpointIndependent
			return res
		}
	}
	var targetSTUN2 string
	if secondarySTUN != "" {
		targetSTUN2 = secondarySTUN
	} else {
		changedAddr := resp1.GetChangedAddress()
		if changedAddr != nil {
			targetSTUN2 = net.JoinHostPort(changedAddr.IP.String(), strconv.Itoa(changedAddr.Port))
		} else {
			host, port, _ := net.SplitHostPort(primarySTUN)
			ips, err := net.LookupIP(host)
			if err == nil && len(ips) > 1 {
				primaryIP, err := net.ResolveIPAddr("ip", host)
				if err != nil {
					return res
				}
				wantIPv4 := network == "udp4"
				wantIPv6 := network == "udp6"
				if network == "udp" {
					wantIPv4 = primaryIP.IP.To4() != nil
					wantIPv6 = !wantIPv4
				}
				for _, ip := range ips {
					if ip.Equal(primaryIP.IP) {
						continue
					}
					isV4 := ip.To4() != nil
					if wantIPv4 && !isV4 {
						continue
					}
					if wantIPv6 && isV4 {
						continue
					}
					targetSTUN2 = net.JoinHostPort(ip.String(), port)
					break
				}
			}
		}
	}
	var mappedAddr2 *net.UDPAddr
	if targetSTUN2 != "" {
		resp2, _, err := performTest(conn, targetSTUN2, network, timeout, false, false)
		if err == nil && resp2 != nil {
			mappedAddr2 = resp2.GetMappedAddress()
		}
	}
	if mappedAddr2 == nil {
		res.Mapping = MappingUnknown
	} else if mappedAddr1.IP.Equal(mappedAddr2.IP) && mappedAddr1.Port == mappedAddr2.Port {
		res.Mapping = MappingEndpointIndependent
	} else {
		res.Mapping = MappingAddressPortDependent
		changedAddr := resp1.GetChangedAddress()
		if changedAddr != nil {
			host, _, _ := net.SplitHostPort(primarySTUN)
			primaryIP := net.ParseIP(host)
			if primaryIP == nil {
				if ipAddr, err := net.ResolveIPAddr("ip", host); err == nil {
					primaryIP = ipAddr.IP
				}
			}
			if primaryIP != nil && changedAddr.Port != 0 {
				altPortSTUN := net.JoinHostPort(primaryIP.String(), strconv.Itoa(changedAddr.Port))
				if altPortSTUN != primarySTUN {
					resp3, _, err := performTest(conn, altPortSTUN, network, timeout, false, false)
					if err == nil && resp3 != nil {
						if mappedAddr3 := resp3.GetMappedAddress(); mappedAddr3 != nil {
							if mappedAddr1.IP.Equal(mappedAddr3.IP) && mappedAddr1.Port == mappedAddr3.Port {
								res.Mapping = MappingAddressDependent
							}
						}
					}
				}
			}
		}
	}
	respF1, _, _ := performTest(conn, primarySTUN, network, timeout, true, true)
	if respF1 != nil {
		res.Filtering = FilteringEndpointIndependent
	} else {
		respF2, _, _ := performTest(conn, primarySTUN, network, timeout, false, true)
		if respF2 != nil {
			res.Filtering = FilteringAddressDependent
		} else {
			res.Filtering = FilteringAddressPortDependent
		}
	}
	if res.Filtering == FilteringEndpointIndependent {
		res.Type = NATFullCone
		if res.Mapping == MappingUnknown {
			res.Mapping = MappingEndpointIndependent
		}
	} else if res.Mapping == MappingEndpointIndependent {
		switch res.Filtering {
		case FilteringAddressDependent:
			res.Type = NATRestricted
		case FilteringAddressPortDependent:
			res.Type = NATPortRestricted
		}
	} else {
		res.Type = NATSymmetric
	}
	return res
}
