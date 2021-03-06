package main

import (
	"io"
	"log"
	"net"
	"os"

	"github.com/FlexibleBroadband/proxy"
)

func main() {
	logger := log.New(os.Stdout, "", log.Ldate|log.Lshortfile)
	listen, err := net.Listen("tcp", "127.0.0.1:9090")

	if err != nil {
		panic(err)
	}
	socks5 := proxy.Socks5Listen{
		HandleConnect: func(addr string) (*net.TCPConn, error) {
			logger.Println("connet addr:=", addr)
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				logger.Println("connect error:=", err)
				return nil, err
			}
			return conn.(*net.TCPConn), nil
		},
		Transport: func(target net.Conn, client net.Conn) error {
			go io.Copy(client, target)
			_, err := io.Copy(target, client)
			return err
		},
		Auth: func(id, pwd []byte) bool {
			logger.Println(len(id), len(pwd))
			logger.Printf("user(%s) pwd(%s)", id, pwd)
			return true
		},
		HandleAssociate: proxy.DefaultHandleAssociate,
		TransportUdp:    proxy.DefaultTransportUdp,

		AddrForClient: "127.0.0.1",

		RawListen: listen,
	}
	socks5.Listen()
}
