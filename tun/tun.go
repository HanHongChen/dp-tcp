package tun

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"

	"github.com/songgao/water"
)

func deriveCIDR(ipStr string, prefix string) (string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("invalid IP: %s", ipStr)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return "", fmt.Errorf("not an IPv4 address: %s", ipStr)
	}
	prefixInt, err := strconv.Atoi(prefix)
	if err != nil {
		return "", fmt.Errorf("invalid prefix (not a number): %s", prefix)
	}

	mask := net.CIDRMask(prefixInt, 32)
	network := ip4.Mask(mask)
	return fmt.Sprintf("%s", network.String()), nil
}

func BringUpUeTunnelDevice(ueTunnelDeviceName string, ip string, routePrefix string) (*water.Interface, error) {
	tunCfg := water.Config{
		DeviceType: water.TUN,
	}
	tunCfg.Name = ueTunnelDeviceName

	tun, err := water.New(tunCfg)
	if err != nil {
		return nil, fmt.Errorf("error creating tunnel device: %v", err)
	}
	route, err := deriveCIDR(ip, routePrefix)
	if err != nil {
		return nil, fmt.Errorf("error deriveCIDR: %v", err)
	}
	// return nil, fmt.Errorf("%s, tun", route)
	cmds := [][]string{
		{"ip", "addr", "add", fmt.Sprintf("%s/32", ip), "dev", ueTunnelDeviceName},
		{"ip", "link", "set", "dev", ueTunnelDeviceName, "up"},
		{"ip", "route", "add", fmt.Sprintf("%s/%s", route, routePrefix), "dev", ueTunnelDeviceName},
	}

	for i, cmd := range cmds {
		fmt.Errorf("now i = : %d", i)
		if err := exec.Command(cmd[0], cmd[1:]...).Run(); err != nil {
			return nil, fmt.Errorf("error bringing up tunnel device: %v", err)
		}
	}

	return tun, nil
}

func BringDownUeTunnelDevice(ueTunnelDeviceName string, ip string, routePrefix string) error {
	route, err := deriveCIDR(ip, routePrefix)
	if err != nil {
		return fmt.Errorf("error deriveCIDR: %v", err)
	}
	cmds := [][]string{
		{"ip", "route", "del", fmt.Sprintf("%s/%s", route, routePrefix), "dev", ueTunnelDeviceName},
		{"ip", "addr", "flush", "dev", ueTunnelDeviceName},
		{"ip", "link", "set", "dev", ueTunnelDeviceName, "down"},
	}

	for _, cmd := range cmds {
		if err := exec.Command(cmd[0], cmd[1:]...).Run(); err != nil {
			return fmt.Errorf("error bringing down tunnel device: %v", err)
		}
	}

	return nil
}
