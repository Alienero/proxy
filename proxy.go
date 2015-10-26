// Copyright © 2015 FlexibleBroadband Team.
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//	      ___ _           _ _     _
//	     / __\ | _____  _(_) |__ | | ___
//	    / _\ | |/ _ \ \/ / | '_ \| |/ _ \
//	   / /   | |  __/>  <| | |_) | |  __/
//	   \/    |_|\___/_/\_\_|_.__/|_|\___|

// The package implement a socks5 server(https://www.ietf.org/rfc/rfc1928.txt)
package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

const (
	Ver = 0x05

	// Socks5 server method.
	// X'00' NO AUTHENTICATION REQUIRED
	//          o  X'01' GSSAPI
	//          o  X'02' USERNAME/PASSWORD
	//          o  X'03' to X'7F' IANA ASSIGNED
	//          o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
	//          o  X'FF' NO ACCEPTABLE METHODS
	NOAUTHENTICATION = 0x00
	USERPASSWORD     = 0x02
	NOTACCEPTMETHOD  = 0xff

	// get request head.
	// o  CMD
	//    o  CONNECT X'01'
	//    o  BIND X'02'
	//    o  UDP ASSOCIATE X'03'
	// o  ATYP   address type of following address
	//    o  IP V4 address: X'01'
	//    o  DOMAINNAME: X'03'
	//    o  IP V6 address: X'04'
	CONNECT    = 0x01
	BIND       = 0x02
	ASSOCIATE  = 0x03
	UDP        = 0x03
	IPv4       = 0x01
	DOMAINNAME = 0x03
	IPv6       = 0x04

	// o  REP    Reply field:
	//            o  X'00' succeeded
	//            o  X'01' general SOCKS server failure
	//            o  X'02' connection not allowed by ruleset
	//            o  X'03' Network unreachable
	//            o  X'04' Host unreachable
	//            o  X'05' Connection refused
	//            o  X'06' TTL expired
	//            o  X'07' Command not supported
	//            o  X'08' Address type not supported
	//            o  X'09' to X'FF' unassigned
	SUCCEEDED = 0x00
)

// AddrSpec is used to return the target AddrSpec
// which may be specified as IPv4, IPv6, or a FQDN
type AddrSpec struct {
	FQDN string
	IP   net.IP
	Port int
}

type Socks5Listen struct {
	EnableAuth   bool
	Auth         func(id, pwd []byte) bool
	HandleConnet func(addr string) (*net.TCPConn, error)
	RawListen    net.Listener
}

// Accept waits for and returns the next connection to the listener.
func (sl *Socks5Listen) Accept() (c Conn, err error) {
	conn, err := sl.RawListen.Accept()
	if err != nil {
		return nil, err
	}
	var needClose = true
	defer func() {
		if needClose {
			conn.Close()
		}
	}()
	// handle shake.
	//  The client connects to the server, and sends a version
	//  identifier/method selection message:

	//                   +----+----------+----------+
	//                   |VER | NMETHODS | METHODS  |
	//                   +----+----------+----------+
	//                   | 1  |    1     | 1 to 255 |
	//                   +----+----------+----------+

	//   The VER field is set to X'05' for this version of the protocol.  The
	//   NMETHODS field contains the number of method identifier octets that
	//   appear in the METHODS field.
	head := make([]byte, 257)
	// make suer must read nmethods.
	n, err := io.ReadAtLeast(conn, head, 2)
	if err != nil {
		return nil, err
	}
	// parser head.
	if head[0] != Ver {
		return nil, fmt.Errorf("Not support version:%v", head[0])
	}
	nmethod := int(head[1])
	msgLen := nmethod + 2
	if n < msgLen {
		if _, err = io.ReadFull(conn, head[n:msgLen]); err != nil {
			return err
		}
	}
	method := NOTACCEPTMETHOD
	if msgLen > 2 {
		var tm int
		for _, i := range head[2:] {
			switch int(i) {
			case NOAUTHENTICATION:
				if NOAUTHENTICATION > tm {
					tm = NOAUTHENTICATION
				}
			case USERPASSWORD:
				if USERPASSWORD > tm {
					tm = USERPASSWORD
				}
			}
		}
		if tm != 0 {
			method = tm
		}
	}
	switch {
	case sl.EnableAuth && method == USERPASSWORD:
		// ok,pass.
	case !sl.EnableAuth && method == NOAUTHENTICATION:
		// ok.pass.
	default:
		_, err = conn.Write([]byte{Ver, NOTACCEPTMETHOD})
		return nil, fmt.Errorf("Not accept method:%v", head[1])
	}
	_, err = conn.Write([]byte{Ver, method})
	if err != nil {
		return nil, err
	}
	if method == USERPASSWORD {
		// This begins with the client producing a
		//   Username/Password request:
		//           +----+------+----------+------+----------+
		//           |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
		//           +----+------+----------+------+----------+
		//           | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
		//           +----+------+----------+------+----------+

		// check the user and password.
		// read username.
		head1 := head[:2]
		if _, err = io.ReadAtLeast(conn, head, 2); err != nil {
			return nil, err
		}
		ulen := int(head1[1])
		if ulen < 1 || ulen > 255 {
			return nil, fmt.Errorf("Error ulen:%v", ulen)
		}
		uname := make([]byte, ulen)
		if _, err = io.ReadAtLeast(conn, uname, ulen); err != nil {
			return nil, err
		}
		head2 := head[:1]
		if _, err = io.ReadAtLeast(conn, head2, 1); err != nil {
			return nil, err
		}
		plen := int(head2[0])
		if plen < 1 || plen > 255 {
			return nil, fmt.Errorf("Error plen:%v", ulen)
		}
		passwd := make([]byte, plen)
		if _, err = io.ReadAtLeast(conn, passwd, plen); err != nil {
			return nil, err
		}
		if !sl.Auth(uname, passwd) {
			// not allower user.
			conn.Write([]byte{0x01, 0x01})
			return nil, fmt.Errorf("User(%s) or Password(%s) error", uname, passwd)
		} else {
			_, err = conn.Write([]byte{0x01, 0x00})
			if err != nil {
				return nil, e
			}
		}
	}
	hostPort, err := sl.getRequest(conn)
	if err != nil {
		return nil, err
	}
	// replay.
	// The server evaluates the request, and
	//  returns a reply formed as follows:
	//       +----+-----+-------+------+----------+----------+
	//       |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	//       +----+-----+-------+------+----------+----------+
	//       | 1  |  1  | X'00' |  1   | Variable |    2     |
	//       +----+-----+-------+------+----------+----------+
	// handle connect.
	local, err := sl.HandleConnet(hostPort)
	if err != nil {
		return nil, err
	}
	bind := AddrSpec{IP: local.IP, Port: local.Port}
	err = sl.sendReply(conn, SUCCEEDED, &bind)
	if err != nil {
		return nil, err
	}
	// TODO: create socks5 conn
}

// sendReply is used to send a reply message
func (sl *Socks5Listen) sendReply(w io.Writer, resp uint8, addr *AddrSpec) error {
	// Format the address
	var addrType uint8
	var addrBody []byte
	var addrPort uint16
	switch {
	case addr == nil:
		addrType = ipv4Address
		addrBody = []byte{0, 0, 0, 0}
		addrPort = 0

	case addr.FQDN != "":
		addrType = DOMAINNAME
		addrBody = append([]byte{byte(len(addr.FQDN))}, addr.FQDN...)
		addrPort = uint16(addr.Port)

	case addr.IP.To4() != nil:
		addrType = ipv4Address
		addrBody = []byte(addr.IP.To4())
		addrPort = uint16(addr.Port)

	case addr.IP.To16() != nil:
		addrType = ipv6Address
		addrBody = []byte(addr.IP.To16())
		addrPort = uint16(addr.Port)

	default:
		return fmt.Errorf("Failed to format address: %v", addr)
	}

	// Format the message
	msg := make([]byte, 6+len(addrBody))
	msg[0] = socks5Version
	msg[1] = resp
	msg[2] = 0 // Reserved
	msg[3] = addrType
	copy(msg[4:], addrBody)
	msg[4+len(addrBody)] = byte(addrPort >> 8)
	msg[4+len(addrBody)+1] = byte(addrPort & 0xff)

	// Send the message
	_, err := w.Write(msg)
	return err
}

func (sl *Socks5Listen) getRequest(conn net.Conn) (string, error) {
	// The SOCKS request is formed as follows:
	//       +----+-----+-------+------+----------+----------+
	//       |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	//       +----+-----+-------+------+----------+----------+
	//       | 1  |  1  | X'00' |  1   | Variable |    2     |
	//       +----+-----+-------+------+----------+----------+
	const (
		lenIPv4   = 3 + 1 + net.IPv4len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv4 + 2port
		lenIPv6   = 3 + 1 + net.IPv6len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv6 + 2port
		lenDmBase = 3 + 1 + 1 + 2           // 3 + 1addrType + 1addrLen + 2port, plus addrLen
	)
	// DST.PORT must 255 + 1
	buf := make([]byte, 262)
	n, err := io.ReadAtLeast(conn, buf, 5)
	if err != nil {
		return "", err
	}
	if buf[0] != Ver {
		return "", fmt.Errorf("Not support version:%v", buf[0])
	}
	switch buf[1] {
	case CONNECT:
		var (
			addrLen   = 0
			perfixLen = 0
		)
		// ATYP
		switch buf[3] {
		case IPv4:
			perfixLen = 4
			addrLen = net.IPv4len
		case DOMAINNAME:
			perfixLen = 5
			addrLen = int(buf[4])
		case IPv6:
			perfixLen = 4
			addrLen = net.IPv6len
		}
		// prot's length is 2.
		reqLen := perfixLen + addrLen + 2
		if n < reqLen {
			if _, err = io.ReadFull(conn, buf[n:reqLen]); err != mil {
				return "", err
			}
		} else if n > reqLen {
			return "", fmt.Errorf("Error request's length:%v", n)
		}
		// get dst's addr and port.
		var host string
		switch buf[3] {
		case IPv4, IPv6:
			host = net.IP(buf[perfixLen : perfixLen+addrLen]).String()
		case DOMAINNAME:
			host = string(buf[perfixLen : perfixLen+addrLen])
		}
		port := binary.BigEndian.Uint16(buf[reqLen-2 : reqLen])
		host = net.JoinHostPort(host, strconv.Itoa(int(port)))
		return host, nil
	case BIND:
		// TODO
		return "", nil
	case ASSOCIATE:
		// TODO
	default:
		return "", fmt.Errorf("Not support command:%v", buf[1])
	}
}

// Close closes the listener.
// Any blocked Accept operations will be unblocked and return errors.
func (sl *Socks5Listen) Close() error {
	return sl.RawListen.Close()
}

// Addr returns the listener's network address.
func (sl *Socks5Listen) Addr() Addr {
	return sl.RawListen.Addr()
}
