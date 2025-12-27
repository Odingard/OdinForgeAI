package collector

import (
	"net"
)

type NetworkInterface struct {
	Name       string   `json:"name"`
	HWAddr     string   `json:"hw_addr"`
	IPv4Addrs  []string `json:"ipv4_addrs"`
	IPv6Addrs  []string `json:"ipv6_addrs"`
	Flags      string   `json:"flags"`
}

type NetworkInfo struct {
	Interfaces []NetworkInterface `json:"interfaces"`
	PrimaryIP  string             `json:"primary_ip"`
}

func GetNetworkInfo() NetworkInfo {
	info := NetworkInfo{
		Interfaces: []NetworkInterface{},
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return info
	}

	for _, iface := range ifaces {
		// Skip loopback and down interfaces for primary IP detection
		isUp := iface.Flags&net.FlagUp != 0
		isLoopback := iface.Flags&net.FlagLoopback != 0

		ni := NetworkInterface{
			Name:      iface.Name,
			HWAddr:    iface.HardwareAddr.String(),
			IPv4Addrs: []string{},
			IPv6Addrs: []string{},
			Flags:     iface.Flags.String(),
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil {
				continue
			}

			if ip4 := ip.To4(); ip4 != nil {
				ni.IPv4Addrs = append(ni.IPv4Addrs, ip4.String())
				// Set primary IP to first non-loopback, up interface's IPv4
				if info.PrimaryIP == "" && isUp && !isLoopback {
					info.PrimaryIP = ip4.String()
				}
			} else {
				ni.IPv6Addrs = append(ni.IPv6Addrs, ip.String())
			}
		}

		info.Interfaces = append(info.Interfaces, ni)
	}

	return info
}
