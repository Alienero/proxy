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
	"log"
	"net"
	"strconv"
	"time"
)

const (
	MaxUdpLen = 80192

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
	RawListen       net.Listener
	EnableAuth      bool
	Auth            func(id, pwd []byte) bool
	HandleConnect   func(addr string) (*net.TCPConn, error)
	HandleAssociate func() (*net.UDPConn, error)
	// You should not close connettions in transport.
	Transport    func(target net.Conn, client net.Conn) error
	TransportUdp func(localConn *net.UDPConn, clientAddr string, stop chan struct{}) error
}

func GetUdpRequest(buffer []byte) (targetHost string, data []byte, err error) {
	// 	+----+------+------+----------+----------+----------+
	//      |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
	//      +----+------+------+----------+----------+----------+
	//      | 2  |  1   |  1   | Variable |    2     | Variable |
	//      +----+------+------+----------+----------+----------+

	//     The fields in the UDP request header are:

	//          o  RSV  Reserved X'0000'
	//          o  FRAG    Current fragment number
	//          o  ATYP    address type of following addresses:
	//             o  IP V4 address: X'01'
	//             o  DOMAINNAME: X'03'
	//             o  IP V6 address: X'04'
	//          o  DST.ADDR       desired destination address
	//          o  DST.PORT       desired destination port
	//          o  DATA     user data
	if len(buffer) > 10 {
		return "", nil, fmt.Errorf("Udp head buffer length(%v) is too small", len(buffer))
	}
	// get host type
	var (
		addrLen   int
		perfixLen int

		host string
		port int
	)
	switch buffer[3] {
	case IPv4:
		addrLen = net.IPv4len
		perfixLen = 4
	case DOMAINNAME:
		addrLen = int(buffer[4])
		perfixLen = 4 + 1
	case IPv6:
		addrLen = net.IPv6len
		perfixLen = 4
	}
	// TODO: don't have enough data.
	switch buffer[3] {
	case IPv4, IPv6:
		host = net.IP(buffer[perfixLen : perfixLen+addrLen]).String()
	case DOMAINNAME:
		host = string(buffer[perfixLen : perfixLen+addrLen])
	}
	port = int(binary.BigEndian.Uint16(buffer[perfixLen+addrLen : perfixLen+addrLen+2]))
	targetHost = net.JoinHostPort(host, strconv.Itoa(int(port)))
	data = buffer[perfixLen+addrLen:]
	return
}

func DefaultHandleAssociate() (*net.UDPConn, error) {
	laddr, err := net.ResolveUDPAddr("udp", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	return net.ListenUDP("udp", laddr)
}

func (sl *Socks5Listen) Listen() (err error) {
	var tempDelay time.Duration
	for {
		conn, e := sl.RawListen.Accept()
		if e != nil {
			if ne, ok := e.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				log.Printf("proxy server: Accept error: %v; retrying in %v", e, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return err
		}
		tempDelay = 0
		go func() {
			if err := sl.serve(conn); err != nil {
				log.Println("serve get an error:", err.Error())
			}
		}()
	}
}

func (sl *Socks5Listen) serve(conn net.Conn) error {
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
		return err
	}
	// parser head.
	if head[0] != Ver {
		return fmt.Errorf("Not support version:%v", head[0])
	}
	nmethod := int(head[1])
	msgLen := nmethod + 2
	if n < msgLen {
		if _, err = io.ReadFull(conn, head[n:msgLen]); err != nil {
			return err
		}
	}
	method := -1
	if msgLen > 2 {
		for _, i := range head[2:msgLen] {
			switch int(i) {
			case NOAUTHENTICATION:
				if NOAUTHENTICATION > method {
					method = NOAUTHENTICATION
				}
			case USERPASSWORD:
				if USERPASSWORD > method {
					method = USERPASSWORD
				}
			}
		}
	}
	switch {
	case sl.EnableAuth && method == USERPASSWORD:
		// ok,pass.
	case !sl.EnableAuth && method == NOAUTHENTICATION:
		// ok.pass.
	default:
		_, err = conn.Write([]byte{Ver, NOTACCEPTMETHOD})
		return fmt.Errorf("Not accept method:%v", method)
	}
	_, err = conn.Write([]byte{Ver, byte(method)})
	if err != nil {
		return err
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
			return err
		}
		ulen := int(head1[1])
		if ulen < 1 || ulen > 255 {
			return fmt.Errorf("Error ulen:%v", ulen)
		}
		uname := make([]byte, ulen)
		if _, err = io.ReadAtLeast(conn, uname, ulen); err != nil {
			return err
		}
		head2 := head[:1]
		if _, err = io.ReadAtLeast(conn, head2, 1); err != nil {
			return err
		}
		plen := int(head2[0])
		if plen < 1 || plen > 255 {
			return fmt.Errorf("Error plen:%v", ulen)
		}
		passwd := make([]byte, plen)
		if _, err = io.ReadAtLeast(conn, passwd, plen); err != nil {
			return err
		}
		if !sl.Auth(uname, passwd) {
			// not allower user.
			conn.Write([]byte{0x01, 0x01})
			return fmt.Errorf("User(%s) or Password(%s) error", uname, passwd)
		} else {
			_, err = conn.Write([]byte{0x01, 0x00})
			if err != nil {
				return err
			}
		}
	}
	hostPort, cmd, err := sl.getRequest(conn)
	if err != nil {
		return err
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
	switch cmd {
	case CONNECT:
		target, err := sl.HandleConnect(hostPort)
		if err != nil {
			return err
		}
		defer target.Close()
		local := target.LocalAddr().(*net.TCPAddr)
		bind := AddrSpec{IP: local.IP, Port: local.Port}
		err = sl.sendReply(conn, SUCCEEDED, &bind)
		if err != nil {
			return err
		}
		return sl.Transport(target, conn)
	case ASSOCIATE:
		target, err := sl.HandleAssociate()
		if err != nil {
			return err
		}
		defer target.Close()
		local := target.LocalAddr().(*net.UDPAddr)
		bind := AddrSpec{IP: local.IP, Port: local.Port}
		err = sl.sendReply(conn, SUCCEEDED, &bind)
		// handle udp.

		return nil
	default:
		return fmt.Errorf("Not support reply cmd:%v", cmd)
	}
}

// sendReply is used to send a reply message
func (sl *Socks5Listen) sendReply(w io.Writer, resp uint8, addr *AddrSpec) error {
	// Format the address
	var addrType uint8
	var addrBody []byte
	var addrPort uint16
	switch {
	case addr == nil:
		addrType = IPv4
		addrBody = []byte{0, 0, 0, 0}
		addrPort = 0

	case addr.FQDN != "":
		addrType = DOMAINNAME
		addrBody = append([]byte{byte(len(addr.FQDN))}, addr.FQDN...)
		addrPort = uint16(addr.Port)

	case addr.IP.To4() != nil:
		addrType = IPv4
		addrBody = []byte(addr.IP.To4())
		addrPort = uint16(addr.Port)

	case addr.IP.To16() != nil:
		addrType = IPv6
		addrBody = []byte(addr.IP.To16())
		addrPort = uint16(addr.Port)

	default:
		return fmt.Errorf("Failed to format address: %v", addr)
	}

	// Format the message
	msg := make([]byte, 6+len(addrBody))
	msg[0] = Ver
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

func (sl *Socks5Listen) getRequest(conn net.Conn) (string, int, error) {
	// The SOCKS request is formed as follows:
	//       +----+-----+-------+------+----------+----------+
	//       |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	//       +----+-----+-------+------+----------+----------+
	//       | 1  |  1  | X'00' |  1   | Variable |    2     |
	//       +----+-----+-------+------+----------+----------+
	// DST.PORT must 255 + 1
	buf := make([]byte, 262)
	n, err := io.ReadAtLeast(conn, buf, 5)
	if err != nil {
		return "", 0, err
	}
	if buf[0] != Ver {
		return "", 0, fmt.Errorf("Not support version:%v", buf[0])
	}
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
		if _, err = io.ReadFull(conn, buf[n:reqLen]); err != nil {
			return "", 0, err
		}
	} else if n > reqLen {
		return "", 0, fmt.Errorf("Error request's length:%v", n)
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
	hostPort := net.JoinHostPort(host, strconv.Itoa(int(port)))
	switch buf[1] {
	case CONNECT:
		return hostPort, CONNECT, nil
	case BIND:
		// TODO
		return "", BIND, fmt.Errorf("Not support cmd:%v", "BIND")
	case ASSOCIATE:
		if host == "0.0.0.0" {
			host = conn.RemoteAddr().(*net.TCPAddr).IP.String()
			hostPort = net.JoinHostPort(host, strconv.Itoa(int(port)))
		}
		return hostPort, ASSOCIATE, fmt.Errorf("Not support cmd:%v", "ASSOCIATE")
	default:
		return "", 0, fmt.Errorf("Not support command:%v", buf[1])
	}
}

// Close closes the listener.
// Any blocked Accept operations will be unblocked and return errors.
func (sl *Socks5Listen) Close() error {
	return sl.RawListen.Close()
}

// Addr returns the listener's network address.
func (sl *Socks5Listen) Addr() net.Addr {
	return sl.RawListen.Addr()
}
