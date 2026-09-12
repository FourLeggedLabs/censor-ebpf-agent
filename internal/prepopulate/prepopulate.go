package prepopulate

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// AllowFunc inserts an address into the firewall allow maps.
type AllowFunc func(netip.Addr) error

// ExistingConnections seeds allow maps from /proc/net/tcp{,6} remote endpoints.
func ExistingConnections(allow AllowFunc) (n int, err error) {
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"} {
		c, e := seedProcNet(path, allow)
		n += c
		if e != nil && !os.IsNotExist(e) && err == nil {
			err = e
		}
	}
	return n, err
}

// ResolveHosts looks up each hostname and allows A/AAAA results (best-effort).
func ResolveHosts(ctx context.Context, hosts []string, allow AllowFunc) (n int) {
	r := net.DefaultResolver
	for _, h := range hosts {
		if strings.ContainsAny(h, "*") {
			continue // globs need DNS proxy JIT
		}
		addrs, err := r.LookupIPAddr(ctx, h)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			addr, ok := netip.AddrFromSlice(a.IP)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if allow(addr) == nil {
				n++
			}
		}
	}
	return n
}

// Run seeds from existing sockets then resolves hosts with a short timeout.
func Run(hosts []string, allow AllowFunc) (conns, resolved int) {
	conns, _ = ExistingConnections(allow)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resolved = ResolveHosts(ctx, hosts, allow)
	return conns, resolved
}

func seedProcNet(path string, allow AllowFunc) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return 0, sc.Err()
	}
	n := 0
	v6 := strings.HasSuffix(path, "6")
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		// remote_address is field 2: IP:port in hex
		parts := strings.Split(fields[2], ":")
		if len(parts) != 2 {
			continue
		}
		addr, err := parseHexIP(parts[0], v6)
		if err != nil || !addr.IsValid() || addr.IsUnspecified() || addr.IsLoopback() {
			continue
		}
		if allow(addr) == nil {
			n++
		}
	}
	return n, sc.Err()
}

func parseHexIP(s string, v6 bool) (netip.Addr, error) {
	if !v6 {
		if len(s) != 8 {
			return netip.Addr{}, fmt.Errorf("bad v4 hex")
		}
		u, err := strconv.ParseUint(s, 16, 32)
		if err != nil {
			return netip.Addr{}, err
		}
		// /proc/net/tcp is little-endian host order on LE machines
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], uint32(u))
		return netip.AddrFrom4(b), nil
	}
	if len(s) != 32 {
		return netip.Addr{}, fmt.Errorf("bad v6 hex")
	}
	var b [16]byte
	for i := 0; i < 4; i++ {
		u, err := strconv.ParseUint(s[i*8:(i+1)*8], 16, 32)
		if err != nil {
			return netip.Addr{}, err
		}
		binary.LittleEndian.PutUint32(b[i*4:], uint32(u))
	}
	return netip.AddrFrom16(b), nil
}
