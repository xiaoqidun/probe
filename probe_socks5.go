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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// SocksAddr SOCKS5域名地址类型
type SocksAddr struct {
	Host string
	Port int
}

// Network 返回网络类型
// 返回: network 网络类型字符串
func (a *SocksAddr) Network() string { return "udp" }

// String 返回地址字符串表示
// 返回: str 地址字符串
func (a *SocksAddr) String() string { return net.JoinHostPort(a.Host, strconv.Itoa(a.Port)) }

// socks5PacketConn SOCKS5数据包连接实现
type socks5PacketConn struct {
	tcpConn    net.Conn
	udpConn    *net.UDPConn
	relayAddr  *net.UDPAddr
	targetAddr net.Addr
}

// ReadFrom 从UDP连接读取数据
// 入参: p 读取缓冲区
// 返回: n 读取字节数, addr 来源地址, err 读取错误
func (c *socks5PacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buf := make([]byte, 65535)
	n, _, err = c.udpConn.ReadFromUDP(buf)
	if err != nil {
		return 0, nil, err
	}
	if n < 10 {
		return 0, nil, nil
	}
	atyp := buf[3]
	var rAddr *net.UDPAddr
	var dataOffset int
	switch atyp {
	case 0x01:
		if n < 10 {
			return 0, nil, errors.New("short packet")
		}
		ip := net.IP(buf[4:8])
		port := binary.BigEndian.Uint16(buf[8:10])
		rAddr = &net.UDPAddr{IP: ip, Port: int(port)}
		dataOffset = 10
	case 0x03:
		dlen := int(buf[4])
		if n < 5+dlen+2 {
			return 0, nil, errors.New("short packet")
		}
		domain := string(buf[5 : 5+dlen])
		port := binary.BigEndian.Uint16(buf[5+dlen : 5+dlen+2])
		ipAddr, err := net.ResolveIPAddr("ip", domain)
		if err != nil {
			return 0, nil, fmt.Errorf("failed to resolve payload domain: %v", err)
		}
		rAddr = &net.UDPAddr{IP: ipAddr.IP, Port: int(port)}
		dataOffset = 5 + dlen + 2
	case 0x04:
		if n < 22 {
			return 0, nil, errors.New("short packet")
		}
		ip := net.IP(buf[4:20])
		port := binary.BigEndian.Uint16(buf[20:22])
		rAddr = &net.UDPAddr{IP: ip, Port: int(port)}
		dataOffset = 22
	default:
		return 0, nil, fmt.Errorf("unknown address type: 0x%x", atyp)
	}
	copy(p, buf[dataOffset:n])
	return n - dataOffset, rAddr, nil
}

// WriteTo 写入数据到目标地址
// 入参: p 数据内容, addr 目标地址
// 返回: n 写入字节数, err 写入错误
func (c *socks5PacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	header := make([]byte, 0, 24)
	header = append(header, 0, 0, 0)
	switch a := addr.(type) {
	case *net.UDPAddr:
		ip4 := a.IP.To4()
		if ip4 != nil {
			header = append(header, 0x01)
			header = append(header, ip4...)
		} else {
			if len(a.IP) == 16 {
				header = append(header, 0x04)
				header = append(header, a.IP...)
			} else {
				return 0, errors.New("unknown ip type")
			}
		}
		portBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(portBuf, uint16(a.Port))
		header = append(header, portBuf...)
	case *SocksAddr:
		header = append(header, 0x03)
		header = append(header, byte(len(a.Host)))
		header = append(header, a.Host...)
		portBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(portBuf, uint16(a.Port))
		header = append(header, portBuf...)
	default:
		return 0, errors.New("unsupported address type")
	}
	finalBuf := append(header, p...)
	_, err = c.udpConn.WriteToUDP(finalBuf, c.relayAddr)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close 关闭连接
// 返回: err 关闭错误
func (c *socks5PacketConn) Close() error {
	err1 := c.tcpConn.Close()
	err2 := c.udpConn.Close()
	if err1 != nil {
		return err1
	}
	return err2
}

// LocalAddr 获取本地地址
// 返回: addr 本地地址
func (c *socks5PacketConn) LocalAddr() net.Addr {
	return c.udpConn.LocalAddr()
}

// SetDeadline 设置读写截止时间
// 入参: t 截止时间
// 返回: err 设置错误
func (c *socks5PacketConn) SetDeadline(t time.Time) error {
	return c.udpConn.SetDeadline(t)
}

// SetReadDeadline 设置读取截止时间
// 入参: t 截止时间
// 返回: err 设置错误
func (c *socks5PacketConn) SetReadDeadline(t time.Time) error {
	return c.udpConn.SetReadDeadline(t)
}

// SetWriteDeadline 设置写入截止时间
// 入参: t 截止时间
// 返回: err 设置错误
func (c *socks5PacketConn) SetWriteDeadline(t time.Time) error {
	return c.udpConn.SetWriteDeadline(t)
}

// DialSocks5UDP 建立SOCKS5 UDP关联
// 入参: proxyAddr 代理服务器地址, network 网络协议(udp/udp4/udp6)
// 返回: conn 数据包连接, err 连接错误
func DialSocks5UDP(proxyAddr, network string) (net.PacketConn, error) {
	var host string
	if strings.Contains(proxyAddr, "://") {
		u, err := url.Parse(proxyAddr)
		if err != nil {
			return nil, err
		}
		host = u.Host
	} else {
		host = proxyAddr
	}
	tcpNetwork := "tcp"
	switch network {
	case "udp4":
		tcpNetwork = "tcp4"
	case "udp6":
		tcpNetwork = "tcp6"
	}
	conn, err := net.DialTimeout(tcpNetwork, host, 5*time.Second)
	if err != nil {
		return nil, err
	}
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		conn.Close()
		return nil, err
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		conn.Close()
		return nil, err
	}
	if buf[0] != 0x05 || buf[1] != 0x00 {
		conn.Close()
		return nil, errors.New("socks5 handshake failed")
	}
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		conn.Close()
		return nil, err
	}
	if header[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5 udp associate failed: 0x%x", header[1])
	}
	var relayIP net.IP
	var relayPort int
	switch header[3] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			conn.Close()
			return nil, err
		}
		relayIP = net.IP(b)
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			conn.Close()
			return nil, err
		}
		domainBuf := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			conn.Close()
			return nil, err
		}
		addr, err := net.ResolveIPAddr("ip", string(domainBuf))
		if err != nil {
			conn.Close()
			return nil, err
		}
		relayIP = addr.IP
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			conn.Close()
			return nil, err
		}
		relayIP = net.IP(b)
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(conn, pb); err != nil {
		conn.Close()
		return nil, err
	}
	relayPort = int(binary.BigEndian.Uint16(pb))
	if relayIP.IsUnspecified() {
		if remoteAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			relayIP = remoteAddr.IP
		}
	}
	relayAddr := &net.UDPAddr{IP: relayIP, Port: relayPort}
	lConn, err := net.ListenUDP(network, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &socks5PacketConn{tcpConn: conn, udpConn: lConn, relayAddr: relayAddr}, nil
}
