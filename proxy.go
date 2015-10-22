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
	"fmt"
	"io"
	"net"
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
)

type Socks5Listen struct {
	EnableAuth bool
	Auth       func(id, pwd []byte) bool
	RawListen  net.Listener
}

// Accept waits for and returns the next connection to the listener.
func (sl *Socks5Listen) Accept() (c Conn, err error) {
	conn, err := sl.RawListen.Accept()
	if err != nil {
		return nil, err
	}
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
