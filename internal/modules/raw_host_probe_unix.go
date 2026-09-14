//go:build !windows

package modules

import (
	"context"
	"encoding/binary"
	"net"
	"syscall"
)

func rawTCPSYNProbe(ctx context.Context, host string, port int) bool {
	return rawTCPHostProbe(ctx, host, port, 12345, 0x02, true)
}

func rawTCPACKProbe(ctx context.Context, host string, port int) bool {
	return rawTCPHostProbe(ctx, host, port, 12346, 0x10, false)
}

func rawTCPHostProbe(ctx context.Context, host string, port int, sourcePort uint16, flags byte, acceptSYNACK bool) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		addrs, err := net.DefaultResolver.LookupHost(ctx, host)
		if err != nil || len(addrs) == 0 {
			return false
		}
		ip = net.ParseIP(addrs[0])
	}
	if ip == nil || ip.To4() == nil {
		return false
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return false
	}
	defer syscall.Close(fd)
	timeout := syscall.Timeval{Sec: 0, Usec: 500000}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout)

	var destination [4]byte
	copy(destination[:], ip.To4())
	if err := syscall.Sendto(fd, buildTCPHeader(sourcePort, uint16(port), flags), 0, &syscall.SockaddrInet4{Port: port, Addr: destination}); err != nil {
		return false
	}
	buffer := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return false
		default:
		}
		n, _, err := syscall.Recvfrom(fd, buffer, 0)
		if err != nil || n < 40 {
			return false
		}
		ipLength := int((buffer[0] & 0x0f) * 4)
		if n < ipLength+20 || int(binary.BigEndian.Uint16(buffer[ipLength:ipLength+2])) != port {
			continue
		}
		responseFlags := buffer[ipLength+13]
		if responseFlags&0x04 != 0 {
			return true
		}
		return acceptSYNACK && responseFlags&0x12 == 0x12
	}
}

func rawTCPTraitsProbe(ctx context.Context, host string, port int) (int, int, error) {
	ip := net.ParseIP(host)
	if ip == nil {
		addrs, err := net.DefaultResolver.LookupHost(ctx, host)
		if err != nil || len(addrs) == 0 {
			return 0, 0, err
		}
		ip = net.ParseIP(addrs[0])
	}
	if ip == nil || ip.To4() == nil {
		return 0, 0, net.UnknownNetworkError("invalid IPv4 target")
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return 0, 0, err
	}
	defer syscall.Close(fd)
	timeout := syscall.Timeval{Sec: 0, Usec: 500000}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout)

	var destination [4]byte
	copy(destination[:], ip.To4())
	sourcePort := uint16(12347)
	if err := syscall.Sendto(fd, buildTCPHeader(sourcePort, uint16(port), 0x02), 0, &syscall.SockaddrInet4{Port: port, Addr: destination}); err != nil {
		return 0, 0, err
	}
	buffer := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return 0, 0, ctx.Err()
		default:
		}
		n, _, err := syscall.Recvfrom(fd, buffer, 0)
		if err != nil || n < 40 {
			return 0, 0, err
		}
		ipLength := int((buffer[0] & 0x0f) * 4)
		if n < ipLength+20 || int(binary.BigEndian.Uint16(buffer[ipLength:ipLength+2])) != port {
			continue
		}
		responseFlags := buffer[ipLength+13]
		if responseFlags&0x12 == 0x12 || responseFlags&0x04 != 0 {
			ttl := int(buffer[8])
			win := int(binary.BigEndian.Uint16(buffer[ipLength+14 : ipLength+16]))
			return ttl, win, nil
		}
	}
}
