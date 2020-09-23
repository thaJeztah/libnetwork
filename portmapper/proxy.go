package portmapper

import (
	"fmt"
	"io"
	"net"

	"github.com/ishidawataru/sctp"
)

type userlandProxy interface {
	Start() error
	Stop() error
}

// dummyProxy just listen on some port, it is needed to prevent accidental
// port allocations on bound port, because without userland proxy we using
// iptables rules and not net.Listen
type dummyProxy struct {
	listener io.Closer
	addr     net.Addr
}

func newDummyProxy(proto string, hostIP net.IP, hostPort int) (userlandProxy, error) {
	switch proto {
	case "tcp":
		addr := &net.TCPAddr{IP: hostIP, Port: hostPort}
		return &dummyProxy{addr: addr}, nil
	case "udp":
		addr := &net.UDPAddr{IP: hostIP, Port: hostPort}
		return &dummyProxy{addr: addr}, nil
	case "sctp":
		addr := &sctp.SCTPAddr{IPAddrs: []net.IPAddr{{IP: hostIP}}, Port: hostPort}
		return &dummyProxy{addr: addr}, nil
	default:
		return nil, fmt.Errorf("Unknown addr type: %s", proto)
	}
}

func (p *dummyProxy) Start() error {
	switch addr := p.addr.(type) {
	case *net.TCPAddr:
		l, err := net.ListenTCP("tcp", addr)
		if err != nil {
			return err
		}
		p.listener = l
	case *net.UDPAddr:
		l, err := net.ListenUDP("udp", addr)
		if err != nil {
			return err
		}
		p.listener = l
	case *sctp.SCTPAddr:
		l, err := sctp.ListenSCTP("sctp", addr)
		if err != nil {
			return err
		}
		p.listener = l
	default:
		return fmt.Errorf("Unknown addr type: %T", p.addr)
	}
	return nil
}

func (p *dummyProxy) Stop() error {
	if p.listener != nil {
		return p.listener.Close()
	}
	return nil
}
