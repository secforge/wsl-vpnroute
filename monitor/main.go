package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
)

// managedRoute tracks a wsltap route this daemon installed, so that:
//   - a prefix wanted by several VPNs is only removed once the last one drops it
//     (refcount via owners), preventing one disconnect from flushing another
//     VPN's routes; and
//   - routes we displaced on other interfaces to install ours are restored when
//     the prefix is finally released.
type managedRoute struct {
	dst       *net.IPNet
	owners    map[string]bool // VPN interfaces currently wanting dst via wsltap
	displaced []netlink.Route // routes removed from other interfaces to install ours
}

// managed is keyed by dst.String(). Accessed only from the main event loop
// goroutine, so it needs no locking.
var managed = map[string]*managedRoute{}

const (
	confFile  = "/etc/vpnroute/vpn-adapters.conf"
	wsltap    = "wsltap"
	gvproxyGW = "192.168.127.1"
	gvproxyIP = "192.168.127.2/24"
	tapMAC    = "5a:94:ef:e4:0c:ee"
	vmPath    = "/usr/local/lib/vpnroute/wsl-vm"
	proxyPath = "/usr/local/lib/vpnroute/wsl-gvproxy.exe"
)

func loadVPNGuids() (map[string]string, error) {
	f, err := os.Open(confFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	guids := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) == 2 {
			guids[strings.ToLower(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return guids, scanner.Err()
}

func ifaceGUID(iface string) string {
	for _, path := range []string{
		fmt.Sprintf("/sys/class/net/%s/device", iface),
		fmt.Sprintf("/sys/class/net/%s", iface),
	} {
		target, err := os.Readlink(path)
		if err != nil {
			continue
		}
		for _, p := range strings.Split(target, "/") {
			if len(p) == 36 && strings.Count(p, "-") == 4 {
				return strings.ToLower(p)
			}
		}
	}
	return ""
}

func isVPNIface(iface string, guids map[string]string) (string, bool) {
	guid := ifaceGUID(iface)
	if guid == "" {
		return "", false
	}
	name, ok := guids[guid]
	return name, ok
}

func skipRoute(r *netlink.Route) bool {
	if r.Dst == nil {
		return true
	}
	ones, _ := r.Dst.Mask.Size()
	if ones == 32 {
		return true
	}
	ip := r.Dst.IP.To4()
	if ip == nil {
		return true
	}
	if ip[0] == 224 || ip[0] == 255 || (ip[0] == 169 && ip[1] == 254) {
		return true
	}
	return false
}

func syncRoutes(iface, vpnName string) {
	vpnLink, err := netlink.LinkByName(iface)
	if err != nil {
		log.Printf("syncRoutes: can't find %s: %v", iface, err)
		return
	}
	routes, err := netlink.RouteList(vpnLink, netlink.FAMILY_V4)
	if err != nil {
		return
	}
	for _, r := range routes {
		if skipRoute(&r) {
			continue
		}
		addRoute(r.Dst, vpnName, iface)
	}
}

// removeIfaceRoutes releases every prefix owned by iface (called when its VPN
// drops). Only routes this interface added are touched; prefixes still wanted
// by another VPN stay in place.
func removeIfaceRoutes(iface, vpnName string) {
	for key, m := range managed {
		if m.owners[iface] {
			releaseRoute(key, iface)
		}
	}
}

// addRoute installs a wsltap route for dst on behalf of ifaceName and records
// ownership. The first owner installs the kernel route and displaces any
// conflicting route on other interfaces (saved for restoration); later owners
// of the same prefix only bump the refcount.
func addRoute(dst *net.IPNet, vpnName, ifaceName string) {
	link, err := netlink.LinkByName(wsltap)
	if err != nil {
		log.Printf("wsltap not found: %v", err)
		return
	}

	key := dst.String()
	m := managed[key]
	if m == nil {
		m = &managedRoute{dst: dst, owners: map[string]bool{}}
		managed[key] = m
	}

	if len(m.owners) == 0 {
		route := &netlink.Route{
			Dst:       dst,
			Gw:        net.ParseIP(gvproxyGW),
			LinkIndex: link.Attrs().Index,
			Priority:  5,
		}
		if err := netlink.RouteReplace(route); err != nil {
			log.Printf("failed to add route %s: %v", dst, err)
			delete(managed, key)
			return
		}
		log.Printf("+ %s via %s dev %s (%s / %s)", dst, gvproxyGW, wsltap, ifaceName, vpnName)

		// Displace shadowing routes on other interfaces, saving them so they can
		// be restored when this prefix is released.
		if existing, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Dst: dst}, netlink.RT_FILTER_DST); err == nil {
			for i := range existing {
				r := existing[i]
				if r.LinkIndex == link.Attrs().Index {
					continue
				}
				if err := netlink.RouteDel(&r); err != nil {
					log.Printf("warning: could not displace route for %s on ifindex %d: %v", dst, r.LinkIndex, err)
					continue
				}
				m.displaced = append(m.displaced, r)
			}
		}
	}

	m.owners[ifaceName] = true
}

// releaseRoute drops ifaceName's claim on the prefix keyed by key. When the last
// owner releases it, the wsltap route is removed and any routes this daemon
// displaced to install it are restored.
func releaseRoute(key, ifaceName string) {
	m := managed[key]
	if m == nil || !m.owners[ifaceName] {
		return
	}
	delete(m.owners, ifaceName)
	if len(m.owners) > 0 {
		return // still wanted by another VPN
	}

	if link, err := netlink.LinkByName(wsltap); err == nil {
		if err := netlink.RouteDel(&netlink.Route{Dst: m.dst, LinkIndex: link.Attrs().Index}); err != nil {
			log.Printf("warning: failed to remove route %s: %v", m.dst, err)
		} else {
			log.Printf("- %s dev %s (%s)", m.dst, wsltap, ifaceName)
		}
	}

	// Restore routes we displaced when first installing this prefix.
	for i := range m.displaced {
		r := m.displaced[i]
		if err := netlink.RouteReplace(&r); err != nil {
			log.Printf("warning: failed to restore displaced route for %s: %v", m.dst, err)
		}
	}
	delete(managed, key)
}

func setupTAP() error {
	// Remove stale tap if present
	if old, err := netlink.LinkByName(wsltap); err == nil {
		netlink.LinkDel(old)
	}

	mac, err := net.ParseMAC(tapMAC)
	if err != nil {
		return fmt.Errorf("invalid MAC: %w", err)
	}

	tap := &netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{
			Name:         wsltap,
			HardwareAddr: mac,
		},
		Mode: netlink.TUNTAP_MODE_TAP,
	}
	if err := netlink.LinkAdd(tap); err != nil {
		return fmt.Errorf("failed to create tap: %w", err)
	}

	link, err := netlink.LinkByName(wsltap)
	if err != nil {
		return err
	}

	addr, err := netlink.ParseAddr(gvproxyIP)
	if err != nil {
		return err
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("failed to add address: %w", err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring up tap: %w", err)
	}

	// Add route to gateway
	gw := net.ParseIP(gvproxyGW)
	if err := netlink.RouteAdd(&netlink.Route{
		Dst:       &net.IPNet{IP: gw, Mask: net.CIDRMask(32, 32)},
		LinkIndex: link.Attrs().Index,
		Scope:     netlink.SCOPE_LINK,
	}); err != nil {
		return fmt.Errorf("failed to add gateway route: %w", err)
	}

	log.Printf("TAP device %s up (%s, gw %s)", wsltap, gvproxyIP, gvproxyGW)
	return nil
}

func teardownTAP() {
	link, err := netlink.LinkByName(wsltap)
	if err != nil {
		return
	}
	netlink.LinkDel(link)
	log.Printf("TAP device %s removed", wsltap)
}

func startTunnel() (*exec.Cmd, error) {
	url := fmt.Sprintf("stdio:%s?listen-stdio=accept&debug=0", proxyPath)
	cmd := exec.Command(vmPath,
		"-url="+url,
		"-iface="+wsltap,
		"-stop-if-exist=",
		"-preexisting=1",
		"-debug=0",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start wsl-vm: %w", err)
	}
	log.Printf("tunnel started (wsl-vm pid %d)", cmd.Process.Pid)
	return cmd, nil
}

func main() {
	if os.Getuid() != 0 {
		log.Fatal("must run as root")
	}

	guids, err := loadVPNGuids()
	if err != nil {
		log.Fatalf("failed to load VPN adapter config: %v", err)
	}
	if len(guids) == 0 {
		log.Fatalf("no VPN adapters in %s — run vpnroute-discover first", confFile)
	}

	if err := setupTAP(); err != nil {
		log.Fatalf("failed to set up TAP: %v", err)
	}

	tunnel, err := startTunnel()
	if err != nil {
		teardownTAP()
		log.Fatalf("failed to start tunnel: %v", err)
	}

	// shuttingDown distinguishes an intentional signal-driven stop from the
	// tunnel dying on its own, so the two cleanup paths don't race or
	// misreport the exit status.
	var shuttingDown atomic.Bool

	// Clean up on exit
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigs
		shuttingDown.Store(true)
		log.Println("shutting down...")
		tunnel.Process.Kill()
		teardownTAP()
		os.Exit(0)
	}()

	// If the tunnel process dies on its own, exit non-zero so systemd restarts
	// us instead of leaving routes pointing at a dead tunnel.
	go func() {
		err := tunnel.Wait()
		if shuttingDown.Load() {
			return // intentional shutdown; the signal handler owns the exit
		}
		log.Printf("wsl-vm exited unexpectedly (%v) — tearing down", err)
		teardownTAP()
		os.Exit(1)
	}()

	log.Printf("vpnroute: watching for VPN route changes (%d known adapters)", len(guids))

	// vpnUp tracks which VPN interfaces have routes installed
	vpnUp := make(map[string]string) // iface -> vpnName

	// Sync routes for any VPN interfaces already up at startup
	if links, err := netlink.LinkList(); err == nil {
		for _, link := range links {
			iface := link.Attrs().Name
			if link.Attrs().OperState != netlink.OperUp {
				continue
			}
			vpnName, ok := isVPNIface(iface, guids)
			if !ok {
				continue
			}
			log.Printf("VPN already up at startup: %s (%s)", vpnName, iface)
			syncRoutes(iface, vpnName)
			vpnUp[iface] = vpnName
		}
	}

	routeCh := make(chan netlink.RouteUpdate)
	doneCh := make(chan struct{})
	if err := netlink.RouteSubscribe(routeCh, doneCh); err != nil {
		tunnel.Process.Kill()
		teardownTAP()
		log.Fatalf("failed to subscribe to route events: %v", err)
	}

	// Poll to catch disconnects — WSL2 mirrored networking doesn't always emit RTM_DELROUTE
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case update := <-routeCh:
			r := update.Route
			if r.LinkIndex == 0 {
				continue
			}
			link, err := netlink.LinkByIndex(r.LinkIndex)
			if err != nil {
				continue
			}
			ifaceName := link.Attrs().Name
			vpnName, ok := isVPNIface(ifaceName, guids)
			if !ok {
				continue
			}
			if skipRoute(&r) {
				continue
			}
			switch update.Type {
			case 24: // RTM_NEWROUTE
				addRoute(r.Dst, vpnName, ifaceName)
				vpnUp[ifaceName] = vpnName
			case 25: // RTM_DELROUTE
				// Only act on deletes that came from the VPN iface itself, not
				// from our own cleanup of the shadowing eth* route in addRoute.
				// We rely on the 3s poll to detect actual VPN disconnects.
			}

		case <-ticker.C:
			for iface, vpnName := range vpnUp {
				link, err := netlink.LinkByName(iface)
				if err != nil || link.Attrs().OperState != netlink.OperUp {
					log.Printf("VPN down: %s (%s)", vpnName, iface)
					removeIfaceRoutes(iface, vpnName)
					delete(vpnUp, iface)
				}
			}
		}
	}
}
