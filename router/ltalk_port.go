/*
   Copyright 2024 Josh Deprez

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package router

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"drjosh.dev/jrouter/atalk"
	"drjosh.dev/jrouter/atalk/atp"
	"drjosh.dev/jrouter/atalk/llap"
	"drjosh.dev/jrouter/atalk/nbp"
	"drjosh.dev/jrouter/atalk/rtmp"
	"drjosh.dev/jrouter/atalk/zip"
	"drjosh.dev/jrouter/meta"
	"drjosh.dev/jrouter/status"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sfiera/multitalk/pkg/ddp"
)

// LTOUDP protocol constants
const (
	LTOUDPMulticastGroup = "239.192.76.84"
	LTOUDPPort           = 1954
)

// Node acquisition constants
const (
	ENQInterval = 250 * time.Millisecond
	ENQAttempts = 8
)

// configureMulticastSocket sets IP_MULTICAST_TTL and optionally IP_MULTICAST_IF
// on the UDP connection. TTL=1 prevents multicast packets from leaking beyond
// the local network. IP_MULTICAST_IF binds outbound multicast to a specific
// interface on multi-homed hosts.
func configureMulticastSocket(conn *net.UDPConn, intfIP net.IP, ttl int) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var opErr error
	err = rawConn.Control(func(fd uintptr) {
		opErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_TTL, ttl)
		if opErr != nil {
			return
		}
		if intfIP != nil {
			mreq := &syscall.IPMreq{}
			copy(mreq.Interface[:], intfIP.To4())
			opErr = syscall.SetsockoptIPMreq(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, mreq)
		}
	})
	if err != nil {
		return err
	}
	return opErr
}

// buildLocalIPSet returns the set of IPv4 addresses on all local interfaces.
func buildLocalIPSet() (map[[4]byte]struct{}, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	set := make(map[[4]byte]struct{})
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipnet.IP.To4()
		if ip4 == nil {
			continue
		}
		set[[4]byte(ip4)] = struct{}{}
	}
	return set, nil
}

// isOwnPacket returns true if the packet was sent by this host—both the sender
// ID must match AND the source IP must belong to a local interface.
func (port *LocalTalkPort) isOwnPacket(senderID []byte, srcAddr *net.UDPAddr) bool {
	if len(senderID) < 4 {
		return false
	}
	if senderID[0] != port.senderID[0] || senderID[1] != port.senderID[1] ||
		senderID[2] != port.senderID[2] || senderID[3] != port.senderID[3] {
		return false
	}
	ip4 := srcAddr.IP.To4()
	if ip4 == nil {
		return false
	}
	_, ok := port.localIPs[[4]byte(ip4)]
	return ok
}

// joinMulticastGroup joins a UDP connection to a multicast group on a specific interface.
func joinMulticastGroup(conn *net.UDPConn, intf *net.Interface, group net.IP) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var opErr error
	err = rawConn.Control(func(fd uintptr) {
		mreq := &syscall.IPMreq{
			Multiaddr: [4]byte(group.To4()),
		}
		if intf != nil {
			// Get interface IP for the mreq
			addrs, _ := intf.Addrs()
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
					copy(mreq.Interface[:], ipnet.IP.To4())
					break
				}
			}
		}
		opErr = syscall.SetsockoptIPMreq(int(fd), syscall.IPPROTO_IP, syscall.IP_ADD_MEMBERSHIP, mreq)
	})
	if err != nil {
		return err
	}
	return opErr
}

// LocalTalkPort handles LocalTalk over UDP (LTOU) traffic.
type LocalTalkPort struct {
	router *Router
	logger *slog.Logger

	// UDP connection
	conn          *net.UDPConn
	multicastAddr *net.UDPAddr
	senderID      [4]byte          // PID-based sender identification
	localIPs      map[[4]byte]struct{} // Local interface IPs for own-packet detection

	// Network configuration
	network  ddp.Network // Single network number (non-extended)
	zoneName string      // Single zone name

	// Node addressing
	myNode        ddp.Node // Our assigned node ID (1-254)
	preferredNode ddp.Node // Preferred starting node for acquisition

	// Node acquisition state
	desiredNode    ddp.Node
	probeAttempts  int
	nodeAcquired   bool
	nodeAcquiredCh chan struct{}
	nodeMu         sync.Mutex

	// Fallback node list (shuffled)
	fallbackNodes []ddp.Node
}

// NewLocalTalkPort creates a new LocalTalk port for the router.
func (router *Router) NewLocalTalkPort(
	network ddp.Network,
	zoneName string,
	intfAddr string,
	preferredNode uint8,
) (*LocalTalkPort, error) {

	// Default preferred node to 254
	if preferredNode == 0 {
		preferredNode = 254
	}

	// Default interface address
	if intfAddr == "" {
		intfAddr = "0.0.0.0"
	}

	// Resolve the multicast address
	multicastAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", LTOUDPMulticastGroup, LTOUDPPort))
	if err != nil {
		return nil, fmt.Errorf("resolve multicast addr: %w", err)
	}

	// Find interface for binding (if specified)
	var intf *net.Interface
	if intfAddr != "0.0.0.0" {
		ifaces, err := net.Interfaces()
		if err != nil {
			return nil, fmt.Errorf("list interfaces: %w", err)
		}
		for i := range ifaces {
			addrs, err := ifaces[i].Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok {
					if ipnet.IP.String() == intfAddr {
						intf = &ifaces[i]
						break
					}
				}
			}
			if intf != nil {
				break
			}
		}
	}

	// Listen on multicast with SO_REUSEPORT to allow multiple LTOU instances on same host
	listenCfg := &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				// Set SO_REUSEADDR and SO_REUSEPORT to allow multiple LTOU instances on same host
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				// SO_REUSEPORT = 15 on Linux
				opErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 15, 1)
			})
			if err != nil {
				return err
			}
			return opErr
		},
	}
	pc, err := listenCfg.ListenPacket(context.Background(), "udp4", fmt.Sprintf(":%d", LTOUDPPort))
	if err != nil {
		return nil, fmt.Errorf("listen udp: %w", err)
	}
	conn := pc.(*net.UDPConn)

	// Configure multicast TTL and outbound interface
	var mcastIntfIP net.IP
	if intfAddr != "0.0.0.0" {
		mcastIntfIP = net.ParseIP(intfAddr).To4()
	}
	if err := configureMulticastSocket(conn, mcastIntfIP, 1); err != nil {
		conn.Close()
		return nil, fmt.Errorf("configure multicast socket: %w", err)
	}

	// Join multicast group
	if intf != nil {
		err = joinMulticastGroup(conn, intf, multicastAddr.IP)
	} else {
		// Join on all interfaces
		ifaces, _ := net.Interfaces()
		for i := range ifaces {
			if ifaces[i].Flags&net.FlagMulticast != 0 && ifaces[i].Flags&net.FlagUp != 0 {
				_ = joinMulticastGroup(conn, &ifaces[i], multicastAddr.IP)
			}
		}
	}
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("join multicast: %w", err)
	}

	// Build fallback node list (all nodes except preferred, shuffled)
	fallbackNodes := make([]ddp.Node, 0, 253)
	for i := 1; i <= 254; i++ {
		if ddp.Node(i) != ddp.Node(preferredNode) {
			fallbackNodes = append(fallbackNodes, ddp.Node(i))
		}
	}
	rand.Shuffle(len(fallbackNodes), func(i, j int) {
		fallbackNodes[i], fallbackNodes[j] = fallbackNodes[j], fallbackNodes[i]
	})

	port := &LocalTalkPort{
		router:         router,
		logger:         router.Logger.With("port", "ltoudp", "network", network),
		conn:           conn,
		multicastAddr:  multicastAddr,
		network:        network,
		zoneName:       zoneName,
		preferredNode:  ddp.Node(preferredNode),
		desiredNode:    ddp.Node(preferredNode),
		nodeAcquiredCh: make(chan struct{}),
		fallbackNodes:  fallbackNodes,
	}

	// Set sender ID to PID
	binary.BigEndian.PutUint32(port.senderID[:], uint32(os.Getpid()))

	// Build local IP set for own-packet detection
	localIPs, err := buildLocalIPSet()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("build local IP set: %w", err)
	}
	port.localIPs = localIPs

	// Add port to router
	router.LocalTalkPorts = append(router.LocalTalkPorts, port)

	// Add port to routing table (non-extended network)
	if _, err := router.RouteTable.UpsertRoute(port, false /* extended */, network, network, 0); err != nil {
		port.logger.Error("Couldn't create route for LocalTalk port", "error", err)
		return nil, err
	}
	if err := router.RouteTable.AddZonesToNetwork(network, zoneName); err != nil {
		port.logger.Error("Couldn't add zone to route", "error", err)
		return nil, err
	}

	port.logger.Info("LocalTalk port created", "multicast", multicastAddr, "zone", zoneName)
	return port, nil
}

// Serve reads packets from UDP and handles them.
func (port *LocalTalkPort) Serve(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	ctx, setStatus, _ := status.AddSimpleItem(ctx, "Inbound")
	defer setStatus("LocalTalk Serve goroutine exited!")
	setStatus("Listening on LTOUDP multicast")

	buf := make([]byte, 1600) // Max LLAP frame + sender ID

	for {
		if ctx.Err() != nil {
			return
		}

		// Set read deadline for periodic context checks
		port.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

		n, srcAddr, err := port.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			port.logger.Error("Couldn't read UDP packet", "error", err)
			return
		}

		// Minimum: 4-byte sender ID + 3-byte LLAP header
		if n < 7 {
			continue
		}

		// Filter own packets by sender ID AND source IP
		if port.isOwnPacket(buf[:4], srcAddr) {
			continue
		}

		promLabels := prometheus.Labels{"network": strconv.Itoa(int(port.network))}
		ltalkPacketsInCounter.With(promLabels).Inc()
		ltalkBytesInCounter.With(promLabels).Add(float64(n))

		// Parse LLAP frame (skip 4-byte sender ID)
		frame, err := llap.Unmarshal(buf[4:n])
		if err != nil {
			ltalkInvalidPacketsInCounter.With(promLabels).Inc()
			port.logger.Debug("Couldn't parse LLAP frame", "error", err)
			continue
		}

		port.handleInboundFrame(ctx, frame)
	}
}

func (port *LocalTalkPort) handleInboundFrame(ctx context.Context, frame *llap.Frame) {
	switch frame.Type {
	case llap.TypeShortDDP:
		port.handleShortDDP(ctx, frame)

	case llap.TypeLongDDP:
		port.handleLongDDP(ctx, frame)

	case llap.TypeENQ:
		port.handleENQ(frame)

	case llap.TypeACK:
		port.handleACK(frame)

	case llap.TypeRTS, llap.TypeCTS:
		// Ignore RTS/CTS - should not be transmitted over UDP
		return

	default:
		// Silently ignore control frames (0x80-0xFF) and type 0 (garbage)
		// Only log unexpected data frame types (0x03-0x7F)
		if frame.Type > 0x02 && frame.Type < 0x80 {
			port.logger.Debug("Unknown LLAP type", "type", frame.Type)
		}
	}
}

func (port *LocalTalkPort) handleShortDDP(ctx context.Context, frame *llap.Frame) {
	pkt, err := llap.ShortDDPToExtPacket(frame, port.network)
	if err != nil {
		// Silently ignore malformed packets - likely from other clients
		return
	}
	port.handleDDPPacket(ctx, pkt)
}

func (port *LocalTalkPort) handleLongDDP(ctx context.Context, frame *llap.Frame) {
	pkt, err := llap.LongDDPToExtPacket(frame)
	if err != nil {
		port.logger.Debug("Couldn't parse long DDP", "error", err)
		return
	}
	port.handleDDPPacket(ctx, pkt)
}

func (port *LocalTalkPort) handleDDPPacket(ctx context.Context, pkt *ddp.ExtPacket) {
	// Wait for node acquisition before handling packets addressed to us
	port.nodeMu.Lock()
	myNode := port.myNode
	acquired := port.nodeAcquired
	port.nodeMu.Unlock()

	if !acquired {
		return
	}

	// Reject packets with invalid source nodes (broadcast or any-router)
	if pkt.SrcNode == 0x00 || pkt.SrcNode == 0xFF {
		return
	}

	// Is the packet for our network?
	if pkt.DstNet != 0 && pkt.DstNet != port.network {
		// Route to another network
		if err := port.router.Forward(ctx, pkt); err != nil {
			port.logger.Debug("DDP: Couldn't forward packet", "error", err)
		}
		return
	}

	// Is the packet for us?
	// Node 0 = any router, 0xFF = broadcast
	if pkt.DstNode != 0 && pkt.DstNode != 0xFF && pkt.DstNode != myNode {
		return
	}

	// Handle by socket
	switch pkt.DstSocket {
	case 1: // RTMP socket
		if err := port.HandleRTMP(ctx, pkt); err != nil {
			port.logger.Error("RTMP: Couldn't handle packet", "error", err)
		}

	case 2: // NIS (NBP socket)
		if err := port.HandleNBP(ctx, pkt); err != nil {
			port.logger.Error("NBP: Couldn't handle packet", "error", err)
		}

	case 4: // AEP socket
		if err := port.router.HandleAEP(ctx, pkt); err != nil {
			port.logger.Error("AEP: Couldn't handle packet", "error", err)
		}

	case 6: // ZIS (ZIP socket)
		if err := port.HandleZIP(ctx, pkt); err != nil {
			port.logger.Error("ZIP: Couldn't handle packet", "error", err)
		}

	default:
		port.logger.Debug("DDP: No handler for socket", "dst-socket", pkt.DstSocket)
	}
}

func (port *LocalTalkPort) handleENQ(frame *llap.Frame) {
	port.nodeMu.Lock()
	defer port.nodeMu.Unlock()

	// If we've acquired a node and someone is asking for it, respond with ACK
	if port.nodeAcquired && frame.DstNode == port.myNode {
		port.sendACK(port.myNode)
		return
	}

	// If we're acquiring and someone wants our desired node, pick a new one
	if !port.nodeAcquired && frame.DstNode == port.desiredNode {
		port.probeAttempts = 0
		port.pickNextNode()
	}
}

func (port *LocalTalkPort) handleACK(frame *llap.Frame) {
	port.nodeMu.Lock()
	defer port.nodeMu.Unlock()

	// If we're acquiring and get an ACK for our desired node, pick a new one
	if !port.nodeAcquired && frame.DstNode == port.desiredNode {
		port.probeAttempts = 0
		port.pickNextNode()
	}
}

func (port *LocalTalkPort) pickNextNode() {
	if len(port.fallbackNodes) == 0 {
		// Rebuild and reshuffle
		port.fallbackNodes = make([]ddp.Node, 0, 254)
		for i := 1; i <= 254; i++ {
			port.fallbackNodes = append(port.fallbackNodes, ddp.Node(i))
		}
		rand.Shuffle(len(port.fallbackNodes), func(i, j int) {
			port.fallbackNodes[i], port.fallbackNodes[j] = port.fallbackNodes[j], port.fallbackNodes[i]
		})
	}
	port.desiredNode = port.fallbackNodes[0]
	port.fallbackNodes = port.fallbackNodes[1:]
	port.logger.Debug("LocalTalk: trying new node", "node", port.desiredNode)
}

// RunNodeAcquisition implements ENQ/ACK node ID acquisition.
func (port *LocalTalkPort) RunNodeAcquisition(ctx context.Context) error {
	ctx, setStatus, _ := status.AddSimpleItem(ctx, "Node Acquisition")
	defer setStatus("Node acquisition stopped!")

	setStatus(fmt.Sprintf("Acquiring node %d", port.desiredNode))

	ticker := time.NewTicker(ENQInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-ticker.C:
			port.nodeMu.Lock()
			if port.probeAttempts >= ENQAttempts {
				// Claim the node
				port.myNode = port.desiredNode
				port.nodeAcquired = true
				close(port.nodeAcquiredCh)
				port.nodeMu.Unlock()

				port.logger.Info("LocalTalk: claimed node", "node", port.myNode)
				setStatus(fmt.Sprintf("Acquired node %d", port.myNode))
				return nil
			}

			// Send ENQ
			node := port.desiredNode
			port.probeAttempts++
			port.nodeMu.Unlock()

			setStatus(fmt.Sprintf("ENQ for node %d (attempt %d/%d)", node, port.probeAttempts, ENQAttempts))
			port.sendENQ(node)
		}
	}
}

func (port *LocalTalkPort) sendENQ(node ddp.Node) {
	frame := llap.NewENQFrame(node)
	port.sendFrame(frame)

	promLabels := prometheus.Labels{"network": strconv.Itoa(int(port.network))}
	ltalkENQCounter.With(promLabels).Inc()
}

func (port *LocalTalkPort) sendACK(node ddp.Node) {
	frame := llap.NewACKFrame(node)
	port.sendFrame(frame)

	promLabels := prometheus.Labels{"network": strconv.Itoa(int(port.network))}
	ltalkACKCounter.With(promLabels).Inc()
}

func (port *LocalTalkPort) sendFrame(frame *llap.Frame) error {
	data := frame.Marshal()

	// Prepend sender ID
	out := make([]byte, 4+len(data))
	copy(out[:4], port.senderID[:])
	copy(out[4:], data)

	_, err := port.conn.WriteToUDP(out, port.multicastAddr)
	if err != nil {
		port.logger.Error("Couldn't send LLAP frame", "error", err)
		return err
	}

	promLabels := prometheus.Labels{"network": strconv.Itoa(int(port.network))}
	ltalkPacketsOutCounter.With(promLabels).Inc()
	ltalkBytesOutCounter.With(promLabels).Add(float64(len(out)))

	return nil
}

// Send sends a DDP packet out this port to the destination node.
func (port *LocalTalkPort) Send(ctx context.Context, pkt *ddp.ExtPacket) error {
	port.nodeMu.Lock()
	srcNode := port.myNode
	port.nodeMu.Unlock()

	frame := llap.ExtPacketToFrame(pkt, port.network, srcNode)
	return port.sendFrame(frame)
}

// Forward implements RouteTarget interface.
func (port *LocalTalkPort) Forward(ctx context.Context, pkt *ddp.ExtPacket) error {
	return port.Send(ctx, pkt)
}

// Broadcast broadcasts a DDP packet (node 0xFF).
// Always uses short DDP (correct for non-extended LocalTalk) and does not
// mutate the input packet.
func (port *LocalTalkPort) Broadcast(pkt *ddp.ExtPacket) error {
	port.nodeMu.Lock()
	srcNode := port.myNode
	port.nodeMu.Unlock()

	frame := llap.ExtPacketToShortDDP(pkt, srcNode)
	frame.DstNode = 0xFF
	return port.sendFrame(frame)
}

// RouteTargetKey returns "LocalTalkPort|network".
func (port *LocalTalkPort) RouteTargetKey() string {
	return fmt.Sprintf("LocalTalkPort|%d", port.network)
}

// Class returns TargetClassDirect.
func (port *LocalTalkPort) Class() TargetClass { return TargetClassDirect }

func (port *LocalTalkPort) String() string {
	return fmt.Sprintf("ltoudp:%d", port.network)
}

const ltalkPortStatusTmpl = `Network: {{.Network}} (non-extended)<br/>
Zone: {{.Zone}}<br/>
Node: {{if .NodeAcquired}}{{.Node}}{{else}}(acquiring){{end}}<br/>`

// StatusCtx returns a context with a new status grouping for this port.
func (port *LocalTalkPort) StatusCtx(ctx context.Context) context.Context {
	ctx, _ = status.AddItem(ctx, fmt.Sprintf("LocalTalk on %d", port.network), ltalkPortStatusTmpl, func(context.Context) (any, error) {
		port.nodeMu.Lock()
		defer port.nodeMu.Unlock()
		return map[string]any{
			"Network":      port.network,
			"Zone":         port.zoneName,
			"Node":         port.myNode,
			"NodeAcquired": port.nodeAcquired,
		}, nil
	})
	return ctx
}

// Assigned returns a channel that is closed when node acquisition is complete.
func (port *LocalTalkPort) Assigned() <-chan struct{} {
	return port.nodeAcquiredCh
}

// Address returns the port's DDP address.
func (port *LocalTalkPort) Address() ddp.Addr {
	port.nodeMu.Lock()
	defer port.nodeMu.Unlock()
	return ddp.Addr{Network: port.network, Node: port.myNode}
}

// HandleRTMP handles RTMP packets for this non-extended network.
func (port *LocalTalkPort) HandleRTMP(ctx context.Context, pkt *ddp.ExtPacket) error {
	switch pkt.Proto {
	case ddp.ProtoRTMPReq:
		req, err := rtmp.UnmarshalRequestPacket(pkt.Data)
		if err != nil {
			return fmt.Errorf("unmarshal RTMP Request: %w", err)
		}

		myAddr := port.Address()

		switch req.Function {
		case rtmp.FunctionRequest:
			// Respond with RTMP Response (non-extended format)
			respPkt := &rtmp.ResponsePacket{
				SenderAddr: myAddr,
				Extended:   false,
				RangeStart: port.network,
				RangeEnd:   port.network,
			}
			respPktRaw, err := respPkt.Marshal()
			if err != nil {
				return fmt.Errorf("marshal RTMP Response: %w", err)
			}
			outDDP := &ddp.ExtPacket{
				ExtHeader: ddp.ExtHeader{
					Size:      uint16(len(respPktRaw)) + atalk.DDPExtHeaderSize,
					Cksum:     0,
					DstNet:    pkt.SrcNet,
					DstNode:   pkt.SrcNode,
					DstSocket: 1,
					SrcNet:    myAddr.Network,
					SrcNode:   myAddr.Node,
					SrcSocket: 1,
					Proto:     ddp.ProtoRTMPResp,
				},
				Data: respPktRaw,
			}
			// Send directly via port.Send since destination is on local network
			return port.Send(ctx, outDDP)

		case rtmp.FunctionRDRSplitHorizon, rtmp.FunctionRDRComplete:
			// Routing Data Request - respond with Data packets
			splitHorizon := req.Function == rtmp.FunctionRDRSplitHorizon
			return port.sendRTMPData(ctx, pkt.SrcNet, pkt.SrcNode, splitHorizon)

		default:
			return fmt.Errorf("TODO: handle RTMP function %d", req.Function)
		}

	case ddp.ProtoRTMPResp:
		// Response/Data from a peer router
		dataPkt, err := rtmp.UnmarshalDataPacket(pkt.Data)
		if err != nil {
			return fmt.Errorf("unmarshal RTMP Data: %w", err)
		}

		peer := &LocalTalkPeer{
			Port:     port,
			PeerAddr: dataPkt.RouterAddr,
		}

		var noZones []ddp.Network
		for _, nt := range dataPkt.NetworkTuples {
			route, err := port.router.RouteTable.UpsertRoute(
				peer,
				nt.Extended,
				nt.RangeStart,
				nt.RangeEnd,
				nt.Distance+1,
			)
			if err != nil {
				return fmt.Errorf("upsert LocalTalk route: %v", err)
			}
			if len(port.router.RouteTable.byNetwork[nt.RangeStart].ZoneNames) == 0 {
				noZones = append(noZones, route.NetStart)
			}
		}

		// Send ZIP Query for networks without zones
		if len(noZones) > 0 {
			qryPkt, err := (&zip.QueryPacket{Networks: noZones}).Marshal()
			if err != nil {
				return fmt.Errorf("marshal ZIP Query: %w", err)
			}
			myAddr := port.Address()
			outDDP := &ddp.ExtPacket{
				ExtHeader: ddp.ExtHeader{
					Size:      uint16(len(qryPkt)) + atalk.DDPExtHeaderSize,
					Cksum:     0,
					SrcNet:    myAddr.Network,
					SrcNode:   myAddr.Node,
					SrcSocket: 6,
					DstNet:    pkt.SrcNet,
					DstNode:   pkt.SrcNode,
					DstSocket: 6,
					Proto:     ddp.ProtoZIP,
				},
				Data: qryPkt,
			}
			if err := port.Send(ctx, outDDP); err != nil {
				return fmt.Errorf("sending ZIP Query: %w", err)
			}
		}

	default:
		return fmt.Errorf("invalid DDP proto %d on RTMP socket", pkt.Proto)
	}

	return nil
}

func (port *LocalTalkPort) sendRTMPData(ctx context.Context, dstNet ddp.Network, dstNode ddp.Node, splitHorizon bool) error {
	myAddr := port.Address()

	// Build routing tuples
	var tuples []rtmp.NetworkTuple
	for r := range port.router.RouteTable.ValidRoutes {
		if r.Target.RouteTargetKey() == port.RouteTargetKey() {
			continue
		}
		ltPeer, _ := r.Target.(*LocalTalkPeer)
		if splitHorizon && ltPeer != nil && ltPeer.Port == port {
			continue
		}
		tuples = append(tuples, rtmp.NetworkTuple{
			Extended:   r.Extended,
			RangeStart: r.NetStart,
			RangeEnd:   r.NetEnd,
			Distance:   r.Distance,
		})
	}

	// First tuple for non-extended network
	first := rtmp.NetworkTuple{
		Extended:   false,
		RangeStart: port.network,
		RangeEnd:   port.network,
		Distance:   0,
	}

	// Build and send Data packets
	rem := tuples
	for {
		chunk := []rtmp.NetworkTuple{first}

		size := 10 // router network + 1 + router node ID + first tuple
		for _, nt := range rem {
			size += nt.Size()
			if size > atalk.DDPMaxDataSize {
				break
			}
			chunk = append(chunk, nt)
		}
		rem = rem[len(chunk)-1:]

		dataPkt := &rtmp.DataPacket{
			RouterAddr:    myAddr,
			Extended:      false,
			NetworkTuples: chunk,
		}
		dataPktRaw, err := dataPkt.Marshal()
		if err != nil {
			return fmt.Errorf("marshal RTMP Data: %w", err)
		}

		outDDP := &ddp.ExtPacket{
			ExtHeader: ddp.ExtHeader{
				Size:      uint16(len(dataPktRaw)) + atalk.DDPExtHeaderSize,
				Cksum:     0,
				DstNet:    dstNet,
				DstNode:   dstNode,
				DstSocket: 1,
				SrcNet:    myAddr.Network,
				SrcNode:   myAddr.Node,
				SrcSocket: 1,
				Proto:     ddp.ProtoRTMPResp,
			},
			Data: dataPktRaw,
		}

		// For broadcast packets (dstNode=0xFF), use port.Broadcast directly
		// since router.Output can't route to "network 0" (this network).
		// For unicast responses, use port.Send since destination is on local network.
		if dstNode == 0xFF {
			if err := port.Broadcast(outDDP); err != nil {
				return err
			}
		} else {
			if err := port.Send(ctx, outDDP); err != nil {
				return err
			}
		}

		if len(rem) == 0 {
			break
		}
	}
	return nil
}

// RunRTMP makes periodic RTMP Data broadcasts on this port.
func (port *LocalTalkPort) RunRTMP(ctx context.Context) error {
	ctx, setStatus, _ := status.AddSimpleItem(ctx, fmt.Sprintf("RTMP on ltoudp:%d", port.network))
	defer setStatus("RTMP loop stopped!")

	setStatus("Awaiting node acquisition")

	// Wait for node acquisition
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-port.nodeAcquiredCh:
	}

	setStatus("Starting broadcast loop")

	first := make(chan struct{}, 1)
	first <- struct{}{}

	bcastTicker := time.NewTicker(10 * time.Second)
	defer bcastTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-bcastTicker.C:
		case <-first:
		}

		setStatus("Broadcasting RTMP Data")
		if err := port.broadcastRTMPData(); err != nil {
			setStatus(fmt.Sprintf("Couldn't broadcast: %v", err))
			port.logger.Error("RTMP: Couldn't broadcast Data", "error", err)
		}
	}
}

func (port *LocalTalkPort) broadcastRTMPData() error {
	return port.sendRTMPData(context.Background(), 0, 0xFF, true)
}

// HandleNBP handles NBP packets.
func (port *LocalTalkPort) HandleNBP(ctx context.Context, pkt *ddp.ExtPacket) error {
	if pkt.Proto != ddp.ProtoNBP {
		return fmt.Errorf("invalid DDP proto %d on NBP socket", pkt.Proto)
	}

	nbpkt, err := nbp.Unmarshal(pkt.Data)
	if err != nil {
		return fmt.Errorf("invalid NBP packet: %w", err)
	}

	port.logger.Debug(fmt.Sprintf("NBP: Got %v id %d with tuples %v", nbpkt.Function, nbpkt.NBPID, nbpkt.Tuples))

	switch nbpkt.Function {
	case nbp.FunctionLkUp:
		// Reply if it's for us
		outDDP, err := port.helloWorldThisIsMe(nbpkt.NBPID, &nbpkt.Tuples[0])
		if err != nil || outDDP == nil {
			return err
		}
		port.logger.Debug("NBP: Replying to LkUp")
		return port.Send(ctx, outDDP)

	case nbp.FunctionBrRq:
		return port.handleNBPBrRq(ctx, pkt, nbpkt)

	case nbp.FunctionFwdReq:
		return port.router.handleNBPFwdReq(ctx, pkt, nbpkt)

	default:
		return fmt.Errorf("TODO: handle NBP function %v", nbpkt.Function)
	}
}

func (port *LocalTalkPort) handleNBPBrRq(ctx context.Context, ddpkt *ddp.ExtPacket, nbpkt *nbp.Packet) error {
	tuple := &nbpkt.Tuples[0]

	// On non-extended networks, translate * to default zone
	if tuple.Zone == "" || tuple.Zone == "*" {
		tuple.Zone = port.zoneName
	}

	routes := port.router.RouteTable.RoutesForZone(tuple.Zone)

	for _, route := range routes {
		if ltPort, isLTPort := route.Target.(*LocalTalkPort); isLTPort {
			// LocalTalk zone - broadcast LkUp directly
			nbpkt.Function = nbp.FunctionLkUp
			nbpRaw, err := nbpkt.Marshal()
			if err != nil {
				return fmt.Errorf("couldn't marshal LkUp: %v", err)
			}

			myAddr := port.Address()
			outDDP := ddp.ExtPacket{
				ExtHeader: ddp.ExtHeader{
					Size:      atalk.DDPExtHeaderSize + uint16(len(nbpRaw)),
					Cksum:     0,
					SrcNet:    myAddr.Network,
					SrcNode:   myAddr.Node,
					SrcSocket: 2,
					DstNet:    0,
					DstNode:   0xFF,
					DstSocket: 2,
					Proto:     ddp.ProtoNBP,
				},
				Data: nbpRaw,
			}

			port.logger.Debug("NBP: broadcasting LkUp", "tuple", tuple)
			if err := ltPort.Broadcast(&outDDP); err != nil {
				return err
			}

			// Also reply if we match
			outDDP2, err := port.helloWorldThisIsMe(nbpkt.NBPID, tuple)
			if err != nil {
				return err
			}
			if outDDP2 != nil {
				port.logger.Debug("NBP: Replying to BrRq directly")
				if err := port.Send(ctx, outDDP2); err != nil {
					return err
				}
			}
			continue
		}

		if etPort, isETPort := route.Target.(*EtherTalkPort); isETPort {
			// EtherTalk zone - zone multicast LkUp directly
			nbpkt.Function = nbp.FunctionLkUp
			nbpRaw, err := nbpkt.Marshal()
			if err != nil {
				return fmt.Errorf("couldn't marshal LkUp: %v", err)
			}

			myAddr := port.Address()
			outDDP := ddp.ExtPacket{
				ExtHeader: ddp.ExtHeader{
					Size:      atalk.DDPExtHeaderSize + uint16(len(nbpRaw)),
					Cksum:     0,
					SrcNet:    myAddr.Network,
					SrcNode:   myAddr.Node,
					SrcSocket: 2,
					DstNet:    0x0000,
					DstNode:   0xFF,
					DstSocket: 2,
					Proto:     ddp.ProtoNBP,
				},
				Data: nbpRaw,
			}

			port.logger.Debug("NBP: zone multicasting LkUp to EtherTalk", "tuple", tuple)
			if err := etPort.ZoneMulticast(tuple.Zone, &outDDP); err != nil {
				return err
			}

			// Also reply if the EtherTalk port matches
			outDDP2, err := etPort.helloWorldThisIsMe(nbpkt.NBPID, tuple)
			if err != nil {
				return err
			}
			if outDDP2 != nil {
				port.logger.Debug("NBP: EtherTalk port replying to BrRq directly")
				if err := port.router.Output(ctx, outDDP2); err != nil {
					return err
				}
			}
			continue
		}

		// Remote zone - send FwdReq
		nbpkt.Function = nbp.FunctionFwdReq
		nbpRaw, err := nbpkt.Marshal()
		if err != nil {
			return fmt.Errorf("couldn't marshal FwdReq: %v", err)
		}

		outDDP := &ddp.ExtPacket{
			ExtHeader: ddp.ExtHeader{
				Size:      atalk.DDPExtHeaderSize + uint16(len(nbpRaw)),
				Cksum:     0,
				SrcNet:    ddpkt.SrcNet,
				SrcNode:   ddpkt.SrcNode,
				SrcSocket: ddpkt.SrcSocket,
				DstNet:    route.NetStart,
				DstNode:   0x00,
				DstSocket: 2,
				Proto:     ddp.ProtoNBP,
			},
			Data: nbpRaw,
		}

		if err := port.router.Output(ctx, outDDP); err != nil {
			return err
		}
	}
	return nil
}

func (port *LocalTalkPort) helloWorldThisIsMe(nbpID uint8, tuple *nbp.Tuple) (*ddp.ExtPacket, error) {
	if tuple.Object != meta.NameVersion && tuple.Object != "=" {
		return nil, nil
	}
	if tuple.Type != "AppleRouter" && tuple.Type != "=" {
		return nil, nil
	}
	if tuple.Zone != port.zoneName && tuple.Zone != "*" && tuple.Zone != "" {
		return nil, nil
	}

	myAddr := port.Address()
	respPkt := &nbp.Packet{
		Function: nbp.FunctionLkUpReply,
		NBPID:    nbpID,
		Tuples: []nbp.Tuple{
			{
				Network:    myAddr.Network,
				Node:       myAddr.Node,
				Socket:     253,
				Enumerator: 0,
				Object:     meta.NameVersion,
				Type:       "AppleRouter",
				Zone:       port.zoneName,
			},
		},
	}
	respRaw, err := respPkt.Marshal()
	if err != nil {
		return nil, fmt.Errorf("couldn't marshal LkUp-Reply: %v", err)
	}

	return &ddp.ExtPacket{
		ExtHeader: ddp.ExtHeader{
			Size:      uint16(len(respRaw)) + atalk.DDPExtHeaderSize,
			Cksum:     0,
			DstNet:    tuple.Network,
			DstNode:   tuple.Node,
			DstSocket: tuple.Socket,
			SrcNet:    myAddr.Network,
			SrcNode:   myAddr.Node,
			SrcSocket: 2,
			Proto:     ddp.ProtoNBP,
		},
		Data: respRaw,
	}, nil
}

// HandleZIP handles ZIP packets.
func (port *LocalTalkPort) HandleZIP(ctx context.Context, pkt *ddp.ExtPacket) error {
	switch pkt.Proto {
	case ddp.ProtoZIP:
		return port.handleZIPZIP(ctx, pkt)

	case ddp.ProtoATP:
		return port.handleZIPATP(ctx, pkt)

	default:
		return fmt.Errorf("invalid DDP proto %d on ZIP socket", pkt.Proto)
	}
}

func (port *LocalTalkPort) handleZIPZIP(ctx context.Context, pkt *ddp.ExtPacket) error {
	zipkt, err := zip.UnmarshalPacket(pkt.Data)
	if err != nil {
		return err
	}

	switch zipkt := zipkt.(type) {
	case *zip.QueryPacket:
		return port.handleZIPQuery(ctx, pkt, zipkt)

	case *zip.ReplyPacket:
		return port.handleZIPReply(zipkt)

	case *zip.GetNetInfoPacket:
		return port.handleZIPGetNetInfo(ctx, pkt, zipkt)

	default:
		return fmt.Errorf("TODO: handle ZIP type %T", zipkt)
	}
}

func (port *LocalTalkPort) handleZIPQuery(ctx context.Context, ddpkt *ddp.ExtPacket, zipkt *zip.QueryPacket) error {
	port.logger.Debug("ZIP: Got Query", "networks", zipkt.Networks)
	networks := port.router.RouteTable.ZonesForNetworks(zipkt.Networks)

	sendReply := func(resp *zip.ReplyPacket) error {
		respRaw, err := resp.Marshal()
		if err != nil {
			return fmt.Errorf("couldn't marshal %T: %w", resp, err)
		}
		myAddr := port.Address()
		outDDP := &ddp.ExtPacket{
			ExtHeader: ddp.ExtHeader{
				Size:      uint16(len(respRaw)) + atalk.DDPExtHeaderSize,
				Cksum:     0,
				DstNet:    ddpkt.SrcNet,
				DstNode:   ddpkt.SrcNode,
				DstSocket: ddpkt.SrcSocket,
				SrcNet:    myAddr.Network,
				SrcNode:   myAddr.Node,
				SrcSocket: 6,
				Proto:     ddp.ProtoZIP,
			},
			Data: respRaw,
		}
		return port.Send(ctx, outDDP)
	}

	// Calculate total size
	size := 2
	for _, zl := range networks {
		for _, z := range zl {
			size += 3 + len(z) // Network number, length byte, string
		}
	}

	if size <= atalk.DDPMaxDataSize {
		// Send one non-extended reply packet with all the data
		return sendReply(&zip.ReplyPacket{
			Extended:     false,
			NetworkCount: uint8(len(networks)),
			Networks:     networks,
		})
	}

	// Send Extended Reply packets, 1 or more for each network
	for nn, zl := range networks {
		rem := zl
		for len(rem) > 0 {
			replySize := 2
			var chunk []string
			for _, z := range rem {
				replySize += 3 + len(z)
				if replySize > atalk.DDPMaxDataSize {
					break
				}
				chunk = append(chunk, z)
			}
			rem = rem[len(chunk):]

			nets := map[ddp.Network][]string{nn: chunk}
			if err := sendReply(&zip.ReplyPacket{
				Extended:     true,
				NetworkCount: uint8(len(zl)),
				Networks:     nets,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (port *LocalTalkPort) handleZIPReply(zipkt *zip.ReplyPacket) error {
	for n, zs := range zipkt.Networks {
		if err := port.router.RouteTable.AddZonesToNetwork(n, zs...); err != nil {
			port.logger.Debug("ZIP: Couldn't add zone to network", "network", n, "zones", zs, "error", err)
		}
	}
	return nil
}

func (port *LocalTalkPort) handleZIPGetNetInfo(ctx context.Context, ddpkt *ddp.ExtPacket, zipkt *zip.GetNetInfoPacket) error {
	port.logger.Debug("ZIP: Got GetNetInfo", "zone", zipkt.ZoneName)

	myAddr := port.Address()
	resp := &zip.GetNetInfoReplyPacket{
		ZoneInvalid:  zipkt.ZoneName != "" && zipkt.ZoneName != port.zoneName,
		UseBroadcast: true, // LocalTalk doesn't have multicast
		OnlyOneZone:  true, // LocalTalk is non-extended, single zone
		NetStart:     port.network,
		NetEnd:       port.network,
		ZoneName:     port.zoneName,
	}

	if resp.ZoneInvalid {
		resp.DefaultZoneName = port.zoneName
	}

	respRaw, err := resp.Marshal()
	if err != nil {
		return fmt.Errorf("couldn't marshal GetNetInfo-Reply: %w", err)
	}

	outDDP := &ddp.ExtPacket{
		ExtHeader: ddp.ExtHeader{
			Size:      uint16(len(respRaw)) + atalk.DDPExtHeaderSize,
			Cksum:     0,
			DstNet:    ddpkt.SrcNet,
			DstNode:   ddpkt.SrcNode,
			DstSocket: ddpkt.SrcSocket,
			SrcNet:    myAddr.Network,
			SrcNode:   myAddr.Node,
			SrcSocket: 6,
			Proto:     ddp.ProtoZIP,
		},
		Data: respRaw,
	}

	return port.Send(ctx, outDDP)
}

func (port *LocalTalkPort) handleZIPATP(ctx context.Context, ddpkt *ddp.ExtPacket) error {
	// ATP-based ZIP requests (GetZoneList, GetLocalZones, GetMyZone)
	atpkt, err := atp.UnmarshalPacket(ddpkt.Data)
	if err != nil {
		return err
	}

	treq, ok := atpkt.(*atp.TReq)
	if !ok {
		// Not a TReq - ignore
		return nil
	}

	gzl, err := zip.UnmarshalTReq(treq)
	if err != nil {
		return err
	}
	// StartIndex is 1-based per spec, but some old clients send 0
	// Treat 0 as 1 for compatibility
	if gzl.StartIndex == 0 {
		gzl.StartIndex = 1
	}

	port.logger.Debug("ZIP/ATP: Got request", "func", gzl.Function, "start", gzl.StartIndex)

	resp := &zip.GetZonesReplyPacket{
		TID:      gzl.TID,
		LastFlag: true,
	}

	switch gzl.Function {
	case zip.FunctionGetZoneList:
		resp.Zones = port.router.RouteTable.AllZoneNames()

	case zip.FunctionGetLocalZones:
		resp.Zones = []string{port.zoneName}

	case zip.FunctionGetMyZone:
		// GetMyZone is relevant for non-extended networks
		resp.Zones = []string{port.zoneName}
	}

	// Trim zones based on start index
	if int(gzl.StartIndex) > len(resp.Zones) {
		resp.Zones = nil
	} else {
		resp.Zones = resp.Zones[gzl.StartIndex-1:]
		size := 0
		for i, z := range resp.Zones {
			size += 1 + len(z)
			if size > atp.MaxDataSize {
				resp.LastFlag = false
				resp.Zones = resp.Zones[:i]
				break
			}
		}
	}

	respATP, err := resp.MarshalTResp()
	if err != nil {
		return err
	}
	ddpBody, err := respATP.Marshal()
	if err != nil {
		return err
	}

	myAddr := port.Address()
	respDDP := &ddp.ExtPacket{
		ExtHeader: ddp.ExtHeader{
			Size:      uint16(len(ddpBody)) + atalk.DDPExtHeaderSize,
			Cksum:     0,
			DstNet:    ddpkt.SrcNet,
			DstNode:   ddpkt.SrcNode,
			DstSocket: ddpkt.SrcSocket,
			SrcNet:    myAddr.Network,
			SrcNode:   myAddr.Node,
			SrcSocket: 6,
			Proto:     ddp.ProtoATP,
		},
		Data: ddpBody,
	}
	return port.Send(ctx, respDDP)
}

// LocalTalkPeer represents a peer router accessible via LocalTalk.
type LocalTalkPeer struct {
	Port     *LocalTalkPort
	PeerAddr ddp.Addr
}

// Forward sends a packet to the peer.
func (p *LocalTalkPeer) Forward(ctx context.Context, pkt *ddp.ExtPacket) error {
	return p.Port.Send(ctx, pkt)
}

// Class returns TargetClassAppleTalkPeer.
func (p *LocalTalkPeer) Class() TargetClass { return TargetClassAppleTalkPeer }

// RouteTargetKey returns a unique key for this peer.
func (p *LocalTalkPeer) RouteTargetKey() string {
	return fmt.Sprintf("LocalTalkPeer|%d.%d", p.PeerAddr.Network, p.PeerAddr.Node)
}
