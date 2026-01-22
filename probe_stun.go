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
	"net"
)

// stunMagicCookie be32用于STUN协议的魔法数
const stunMagicCookie = 0x2112A442

// bindRequest STUN绑定请求消息类型
const bindRequest = 0x0001

// bindResponse STUN绑定响应消息类型
const bindResponse = 0x0101

// attrMappedAddress 映射地址属性类型
const attrMappedAddress = 0x0001

// attrChangeRequest 修改请求属性类型
const attrChangeRequest = 0x0003

// attrChangedAddress 修改后地址属性类型
const attrChangedAddress = 0x0005

// attrXorMappedAddress 异或映射地址属性类型
const attrXorMappedAddress = 0x0020

// attrOtherAddress 其他地址属性类型
const attrOtherAddress = 0x802c

// stunHeader STUN消息头部结构
type stunHeader struct {
	Type   uint16
	Length uint16
	Cookie uint32
	ID     [12]byte
}

// stunMessage STUN消息完整结构
type stunMessage struct {
	Header     stunHeader
	Attributes []stunAttribute
}

// stunAttribute STUN属性结构
type stunAttribute struct {
	Type   uint16
	Length uint16
	Value  []byte
}

// encodeSTUNRequest 构造并编码STUN绑定请求消息
// 入参: id 事务ID, changeIP 是否请求改变IP, changePort 是否请求改变端口
// 返回: data 编码后的二进制数据
func encodeSTUNRequest(id [12]byte, changeIP, changePort bool) []byte {
	buf := make([]byte, 1024)
	binary.BigEndian.PutUint16(buf[0:2], bindRequest)
	binary.BigEndian.PutUint32(buf[4:8], stunMagicCookie)
	copy(buf[8:20], id[:])
	offset := 20
	if changeIP || changePort {
		binary.BigEndian.PutUint16(buf[offset:offset+2], attrChangeRequest)
		binary.BigEndian.PutUint16(buf[offset+2:offset+4], 4)
		offset += 4
		val := uint32(0)
		if changeIP {
			val |= 0x04
		}
		if changePort {
			val |= 0x02
		}
		binary.BigEndian.PutUint32(buf[offset:offset+4], val)
		offset += 4
	}
	binary.BigEndian.PutUint16(buf[2:4], uint16(offset-20))
	return buf[:offset]
}

// decodeSTUNResponse 解析STUN响应消息
// 入参: data 接收到的二进制数据, txID 期望的事务ID
// 返回: msg 解析后的消息结构体指针, err 解析错误信息
func decodeSTUNResponse(data []byte, txID [12]byte) (*stunMessage, error) {
	if len(data) < 20 {
		return nil, errors.New("response too short")
	}
	msgType := binary.BigEndian.Uint16(data[0:2])
	if msgType != bindResponse {
		return nil, fmt.Errorf("unexpected message type: 0x%x", msgType)
	}
	length := binary.BigEndian.Uint16(data[2:4])
	if len(data) < 20+int(length) {
		return nil, errors.New("incomplete message")
	}
	cookie := binary.BigEndian.Uint32(data[4:8])
	if string(data[8:20]) != string(txID[:]) {
		return nil, errors.New("transaction id mismatch")
	}
	msg := &stunMessage{Header: stunHeader{Type: msgType, Length: length, Cookie: cookie, ID: txID}}
	offset := 20
	end := 20 + int(length)
	for offset < end {
		if offset+4 > end {
			break
		}
		attrType := binary.BigEndian.Uint16(data[offset : offset+2])
		attrLen := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4
		if offset+int(attrLen) > end {
			break
		}
		val := make([]byte, attrLen)
		copy(val, data[offset:offset+int(attrLen)])
		msg.Attributes = append(msg.Attributes, stunAttribute{Type: attrType, Length: attrLen, Value: val})
		offset += int(attrLen)
		padding := (4 - (int(attrLen) % 4)) % 4
		offset += padding
	}
	return msg, nil
}

// parseAddress 解析STUN属性中的地址信息
// 入参: attrType 属性类型, data 属性值数据
// 返回: addr 解析出的UDP地址, err 解析错误信息
func parseAddress(attrType uint16, data []byte) (*net.UDPAddr, error) {
	if len(data) < 4 {
		return nil, errors.New("attribute too short")
	}
	family := data[1]
	port := binary.BigEndian.Uint16(data[2:4])
	ipLen := 4
	if family == 0x02 {
		ipLen = 16
	} else if family != 0x01 {
		return nil, fmt.Errorf("unknown address family: %d", family)
	}
	if len(data) < 4+ipLen {
		return nil, errors.New("invalid address length")
	}
	ip := make(net.IP, ipLen)
	copy(ip, data[4:4+ipLen])
	if attrType == attrXorMappedAddress {
		port ^= uint16(stunMagicCookie >> 16)
		if ipLen == 4 {
			mc := make([]byte, 4)
			binary.BigEndian.PutUint32(mc, stunMagicCookie)
			for i := 0; i < 4; i++ {
				ip[i] ^= mc[i]
			}
		}
	}
	return &net.UDPAddr{IP: ip, Port: int(port)}, nil
}

// GetMappedAddress 获取消息中的映射地址属性
// 返回: addr 映射的UDP地址
func (m *stunMessage) GetMappedAddress() *net.UDPAddr {
	for _, attr := range m.Attributes {
		if attr.Type == attrXorMappedAddress {
			if addr, err := parseAddress(attr.Type, attr.Value); err == nil {
				return addr
			}
		}
	}
	for _, attr := range m.Attributes {
		if attr.Type == attrMappedAddress {
			if addr, err := parseAddress(attr.Type, attr.Value); err == nil {
				return addr
			}
		}
	}
	return nil
}

// GetChangedAddress 获取消息中的变更地址属性
// 返回: addr 变更的UDP地址
func (m *stunMessage) GetChangedAddress() *net.UDPAddr {
	for _, attr := range m.Attributes {
		if attr.Type == attrChangedAddress {
			if addr, err := parseAddress(attr.Type, attr.Value); err == nil {
				return addr
			}
		}
	}
	for _, attr := range m.Attributes {
		if attr.Type == attrOtherAddress {
			if addr, err := parseAddress(attr.Type, attr.Value); err == nil {
				return addr
			}
		}
	}
	return nil
}
