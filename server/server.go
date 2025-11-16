package server

import (
	"context"
	"crypto/sha512"
	"sync"

	"github.com/Alonza0314/dp-tcp/constant"
	"github.com/Alonza0314/dp-tcp/logger"
	"github.com/Alonza0314/dp-tcp/model"
	"github.com/Alonza0314/dp-tcp/tun"
	"github.com/Alonza0314/dp-tcp/util"
	"github.com/songgao/water"
)

type DpTcpServer struct {
	tcpServer1 *tcpServer
	tcpServer2 *tcpServer

	tunnelDeviceName  string
	tunnelDeviceIP    string
	tunnelRoutePrefix string

	tunnelDevice *water.Interface

	readFromTun   chan []byte
	readFromTcp1  chan []byte
	readFromTcp2  chan []byte
	writeToTcp1   chan []byte
	writeToTcp2   chan []byte
	writeToTun    chan []byte
	eliminateChan chan []byte

	// packetMap *hashmap.Map[uint64, struct{}]

	packetMap sync.Map // key: uint64, value: struct{}
	iperfMap  sync.Map

	*logger.ServerLogger
}

func NewDpTcpServer(config *model.ServerConfig, serverLogger *logger.ServerLogger) *DpTcpServer {
	return &DpTcpServer{
		tcpServer1: newTcpServer(config.ServerIE.TCP1ListenAddr, config.ServerIE.TCP1ListenPort),
		tcpServer2: newTcpServer(config.ServerIE.TCP2ListenAddr, config.ServerIE.TCP2ListenPort),

		tunnelDeviceName:  config.ServerIE.TunnelDevice.Name,
		tunnelDeviceIP:    config.ServerIE.TunnelDevice.IP,
		tunnelRoutePrefix: config.ServerIE.TunnelDevice.RoutePrefix,

		readFromTun:  make(chan []byte),
		readFromTcp1: make(chan []byte),
		readFromTcp2: make(chan []byte),
		writeToTcp1:  make(chan []byte),
		writeToTcp2:  make(chan []byte),

		eliminateChan: make(chan []byte),

		writeToTun: make(chan []byte),

		ServerLogger: serverLogger,
	}
}

func (s *DpTcpServer) Start(ctx context.Context) error {
	s.ServerLog.Infof("DpTcpServer starting...")

	if err := s.tcpServer1.listen(); err != nil {
		s.Tcp1Log.Errorf("TCP 1 server listen failed: %v", err)
		return err
	}
	s.Tcp1Log.Infof("TCP 1 server started at %s:%d", s.tcpServer1.listenAddr, s.tcpServer1.listenPort)

	if err := s.tcpServer2.listen(); err != nil {
		s.Tcp2Log.Errorf("TCP 2 server listen failed: %v", err)
		if err := s.tcpServer1.close(); err != nil {
			s.Tcp1Log.Errorf("TCP 1 server close failed: %v", err)
		}
		return err
	}
	s.Tcp2Log.Infof("TCP 2 server started at %s:%d", s.tcpServer2.listenAddr, s.tcpServer2.listenPort)

	if err := s.tcpServer1.accept(); err != nil {
		s.Tcp1Log.Errorf("TCP 1 server accept failed: %v", err)
		return err
	}

	if err := s.tcpServer2.accept(); err != nil {
		s.Tcp2Log.Errorf("TCP 2 server accept failed: %v", err)
		return err
	}

	if err := s.setupTunnelDevice(); err != nil {
		s.ServerLog.Errorf("Tunnel device setup failed: %v", err)
		if err := s.tcpServer1.close(); err != nil {
			s.Tcp1Log.Errorf("TCP 1 server close failed: %v", err)
		}
		if err := s.tcpServer2.close(); err != nil {
			s.Tcp2Log.Errorf("TCP 2 server close failed: %v", err)
		}
		return err
	}

	go s.readFromTunnelDevice(ctx)
	go s.dispatchFromTunnel(ctx)
	go s.sendToTcp1(ctx)
	go s.sendToTcp2(ctx)

	go s.readFromTcp1Connection(ctx)
	go s.readFromTcp2Connection(ctx)
	go s.writeToTunnelDevice(ctx)
	// go s.startEliminatorWorkers(ctx)

	// go s.packetDuplicate(ctx)
	go s.packetEliminate(ctx)

	s.ServerLog.Infof("DpTcpServer started")
	return nil
}

func (s *DpTcpServer) Stop() {
	s.ServerLog.Infof("DpTcpServer stopping...")

	close(s.readFromTun)
	close(s.readFromTcp1)
	close(s.readFromTcp2)

	if err := s.cleanUpTunnelDevice(); err != nil {
		s.TunLog.Errorf("Tunnel device cleanup failed: %v", err)
	}

	if err := s.tcpServer2.close(); err != nil {
		s.Tcp2Log.Errorf("TCP 2 server close failed: %v", err)
	}
	s.Tcp2Log.Infof("TCP 2 server stopped")

	if err := s.tcpServer1.close(); err != nil {
		s.Tcp1Log.Errorf("TCP 1 server close failed: %v", err)
	}
	s.Tcp1Log.Infof("TCP 1 server stopped")

	s.ServerLog.Infof("DpTcpServer stopped")
}

func (s *DpTcpServer) setupTunnelDevice() error {
	s.TunLog.Infof("Setting up tunnel device %s with IP %s", s.tunnelDeviceName, s.tunnelDeviceIP)

	tun, err := tun.BringUpUeTunnelDevice(s.tunnelDeviceName, s.tunnelDeviceIP, s.tunnelRoutePrefix)
	if err != nil {
		return err
	}
	s.tunnelDevice = tun
	s.TunLog.Infof("Tunnel device %s with IP %s set up", s.tunnelDeviceName, s.tunnelDeviceIP)
	return nil
}

func (s *DpTcpServer) cleanUpTunnelDevice() error {
	s.TunLog.Infof("Cleaning up tunnel device %s", s.tunnelDeviceName)

	if err := tun.BringDownUeTunnelDevice(s.tunnelDeviceName, s.tunnelDeviceIP, s.tunnelRoutePrefix); err != nil {
		return err
	}

	s.TunLog.Infof("Tunnel device %s cleaned up", s.tunnelDeviceName)
	return nil
}

func (s *DpTcpServer) readFromTunnelDevice(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			buffer := make([]byte, constant.BUFFER_SIZE)
			n, err := s.tunnelDevice.Read(buffer)
			if err != nil {
				s.ServerLog.Errorf("Read from tunnel device failed: %v", err)
				continue
			}
			if !util.IsValidIPPacket(buffer) {
				s.ServerLog.Debugf("Invalid IP packet read from TUN device, skipping (size: %d)", n)
				continue
			}

			data := make([]byte, n)
			copy(data, buffer[:n])
			s.readFromTun <- data
		}
	}
}

// Read from udp server 1 and forward to tunnel device
func (s *DpTcpServer) readFromTcp1Connection(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			buffer := make([]byte, constant.BUFFER_SIZE)
			n, err := s.tcpServer1.read(buffer)
			if err != nil {
				s.ServerLog.Errorf("TCP 1 server read failed: %v", err)
				continue
			}

			data := make([]byte, n)
			copy(data, buffer[:n])
			if !util.IsValidIPPacket(data) {
				s.ServerLog.Debugf("Invalid IP packet read from TCP conn 1, skipping (size: %d)", n)
				continue
			}

			s.readFromTcp1 <- data

		}
	}
}

func (s *DpTcpServer) readFromTcp2Connection(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			buffer := make([]byte, constant.BUFFER_SIZE)
			n, err := s.tcpServer2.read(buffer)
			if err != nil {
				s.ServerLog.Errorf("TCP 2 server read failed: %v", err)
				continue
			}
			data := make([]byte, n)
			copy(data, buffer[:n])
			if !util.IsValidIPPacket(buffer) {
				s.ServerLog.Debugf("Invalid IP packet read from TCP conn 2, skipping (size: %d)", n)
				continue
			}

			s.readFromTcp2 <- data
		}
	}
}

func (s *DpTcpServer) writeToTunnelDevice(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():

			return
		case data := <-s.writeToTun:
			if _, err := s.tunnelDevice.Write(data); err != nil {
				s.ServerLog.Errorf("Write to tunnel device failed: %v", err)
			}
		}
	}
}

// func (s *DpTcpServer) startEliminatorWorkers(ctx context.Context) {
// 	for {
// 		select {
// 		case <-ctx.Done():
// 			return
// 		case packet := <-s.eliminateChan:
// 			if s.packetEliminate(packet) {
// 				continue
// 			}
// 			s.writeToTun <- packet
// 		}
// 	}

// }

// // true: packet eliminated, false: packet passed
// func (s *DpTcpServer) packetEliminate(packet []byte) bool {
// 	if isIperf, seq := util.IsIperf3DatagramWithTCP(packet); isIperf {
// 		// fmt.Printf("進來 %d\n", seq)
// 		_, loaded := s.iperfMap.LoadOrStore(seq, struct{}{})
// 		// atomic.AddUint64(&s.dupCount, 1)

// 		if loaded {
// 			// fmt.Printf("%d 重複\n", seq)
// 			s.TunLog.Debugf("Eliminated iperf3 packet seq %d", seq)
// 			s.TunLog.Tracef("Eliminated iperf3 packet seq %d, %x", seq, packet)

// 			// atomic.AddUint64(&s.dupSeq, 1)
// 			return true
// 			// return false
// 		}
// 	} else {
// 		// non-iperf3 packet elimination based on hash
// 		h := sha512.Sum512(packet)
// 		_, loaded := s.packetMap.LoadOrStore(h, struct{}{})
// 		if loaded {
// 			s.TunLog.Debugf("Eliminated packet %d", h)
// 			s.TunLog.Tracef("Eliminated packet %d, %x", h, packet)

// 			return true
// 			// return false
// 		}
// 	}
// 	return false
// }

// Dispatch packets read from tunnel device to all connected UDP clients
func (s *DpTcpServer) dispatchFromTunnel(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case data := <-s.readFromTun:
			s.writeToTcp1 <- data
			s.writeToTcp2 <- data
		}
	}
}

func (s *DpTcpServer) sendToTcp1(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case data := <-s.writeToTcp1:
			if n, err := s.tcpServer1.write(data); err != nil {
				s.TunLog.Errorf("Error writing to TCP 1 server: %v", err)
			} else {
				s.TunLog.Debugf("Wrote %d bytes to TCP 1 server", n)
			}
		}
	}
}

func (s *DpTcpServer) sendToTcp2(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case data := <-s.writeToTcp2:
			if n, err := s.tcpServer2.write(data); err != nil {
				s.TunLog.Errorf("Error writing to TCP 2 server: %v", err)
			} else {
				s.TunLog.Debugf("Wrote %d bytes to TCP 2 server", n)
			}

		}
	}
}

// func (s *DpTcpServer) packetDuplicate(ctx context.Context) {
// 	for {
// 		select {
// 		case <-ctx.Done():
// 			return
// 		case data := <-s.readFromTun:
// 			data1 := make([]byte, len(data))
// 			copy(data1, data)
// 			data2 := make([]byte, len(data))
// 			copy(data2, data)

// 			go func() {
// 				if n, err := s.tcpServer1.write(data1); err != nil {
// 					s.TunLog.Errorf("Error writing to TCP 1 server: %v", err)
// 				} else {
// 					s.TunLog.Debugf("Wrote %d bytes to TCP 1 server", n)
// 				}

// 			}()
// 			go func() {
// 				if n, err := s.tcpServer2.write(data2); err != nil {
// 					s.TunLog.Errorf("Error writing to TCP 2 server: %v", err)
// 				} else {
// 					s.TunLog.Debugf("Wrote %d bytes to TCP 2 server", n)
// 				}
// 			}()
// 		}
// 	}
// }

func (s *DpTcpServer) packetEliminate(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case packet := <-s.readFromTcp1:
			go s.packetEliminateMain(packet)
		case packet := <-s.readFromTcp2:
			go s.packetEliminateMain(packet)
		}
	}
}

func (s *DpTcpServer) packetEliminateMain(packet []byte) {
	h := sha512.Sum512(packet)
	_, loaded := s.packetMap.LoadOrStore(h, struct{}{})
	if loaded {
		s.TunLog.Debugf("Eliminated packet %d", h)
		s.TunLog.Tracef("Eliminated packet %d, %x", h, packet)
		return
	}
	s.writeToTun <- packet
	s.TunLog.Debugf("Packet %d stored", h)
	s.TunLog.Tracef("Packet %d stored, %x", h, packet)
}
