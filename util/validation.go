package util

import "fmt"

func IsIperf3DatagramWithUDP(data []byte) (bool, uint64) {
	// Basic IPv4 checks
	if !IsValidIPPacket(data) {
		return false, 0
	}

	// Must be UDP
	if !IsUDPPacket(data) {
		return false, 0
	}

	// IP header length (IHL) in bytes
	ihl := int(data[0]&0x0F) * 4

	// Ensure we have UDP header (8 bytes) present
	if len(data) < ihl+8 {
		return false, 0
	}

	// UDP payload starts after IP header + 8 bytes UDP header
	udpPayload := data[ihl+8:]

	// iperf3 UDP datagram uses at least 12 bytes of header in payload
	// (we expect sequence number at payload offset 8..11)
	if len(udpPayload) < 12 {
		// It's a UDP packet but too short to contain iperf3 header/sequence
		return false, 0
	}

	// Extract iperf3 sequence number (32-bit big-endian) at offset 8
	seq := uint64(udpPayload[8])<<24 |
		uint64(udpPayload[9])<<16 |
		uint64(udpPayload[10])<<8 |
		uint64(udpPayload[11])

	return true, seq
}

// extractIperf3SeqNum extracts iperf3 sequence number from IP packet
func ExtractIperf3SeqNum(ipPacket []byte) (uint64, error) {
	fmt.Printf("=== PACKET STRUCTURE ANALYSIS ===\n")
	fmt.Printf("Total packet length: %d bytes\n", len(ipPacket))

	fmt.Printf("length of ipPacket: %d\n", len(ipPacket))
	// Check if we have Linux cooked capture header (16 bytes)

	// Basic IP header validation
	if len(ipPacket) < 20 {
		return 0, fmt.Errorf("packet too short for IP header")
	} else {
		fmt.Printf("Version: %02x, Len: %02x, Protocol(UDP 0x11, TCP 0x06):  %02x\n",
			(ipPacket[0] >> 4), (ipPacket[0] & 0x0F), ipPacket[9])
	}

	// Check if it's IPv4
	if (ipPacket[0] >> 4) != 4 {
		return 0, fmt.Errorf("not an IPv4 packet")
	}

	// Get IP header length
	ihl := int(ipPacket[0]&0x0F) * 4
	// Check if it's UDP (protocol 17)
	if ipPacket[9] != 17 {
		fmt.Printf("Protocol field: %d\n", ipPacket[9])
		return 0, fmt.Errorf("not a UDP packet")
	}

	udpPayloadStart := ihl + 8
	if len(ipPacket) < udpPayloadStart {
		return 0, fmt.Errorf("packet too short for UDP header")
	}

	// Extract UDP payload (skip IP header + 8 bytes UDP header)
	if len(ipPacket) < udpPayloadStart+12 {
		return 0, fmt.Errorf("packet too short for iperf3 header")
	}

	udpPayload := ipPacket[udpPayloadStart:]

	// Extract iperf3 sequence number (32-bit, big-endian, at offset 0)
	seqNum := uint64(udpPayload[8])<<24 |
		uint64(udpPayload[9])<<16 |
		uint64(udpPayload[10])<<8 |
		uint64(udpPayload[11])

	fmt.Printf("Extracted iperf3 sequence number: %d\n", seqNum)
	return seqNum, nil
}

// IsValidIPPacket checks if the data is a valid IPv4 packet
func IsValidIPPacket(data []byte) bool {
	if len(data) < 20 {
		return false
	}

	version := data[0] >> 4
	if version != 4 {
		return false
	}

	ihl := data[0] & 0x0F
	if ihl < 5 {
		return false
	}

	totalLength := int(data[2])<<8 | int(data[3])
	if totalLength < 20 || totalLength > len(data) {
		return false
	}

	// Additional check: ensure it's not all zeros or invalid patterns
	if data[0] == 0 && data[1] == 0 && data[2] == 0 && data[3] == 0 {
		return false
	}

	return true
}

// IsValidIPPacketVerbose checks if the data is a valid IPv4 packet with detailed error reporting
func IsValidIPPacketVerbose(data []byte) (bool, string) {
	if len(data) < 20 {
		return false, "packet too short"
	}

	version := data[0] >> 4
	if version != 4 {
		return false, "not IPv4"
	}

	ihl := data[0] & 0x0F
	if ihl < 5 {
		return false, "invalid header length"
	}

	totalLength := int(data[2])<<8 | int(data[3])
	if totalLength < 20 || totalLength > len(data) {
		return false, "invalid total length"
	}

	// Additional check: ensure it's not all zeros or invalid patterns
	if data[0] == 0 && data[1] == 0 && data[2] == 0 && data[3] == 0 {
		return false, "packet appears to be all zeros"
	}

	return true, ""
}

// IsUDPPacket checks if the IP packet contains UDP payload
func IsUDPPacket(data []byte) bool {
	if len(data) < 20 {
		return false
	}

	// Check if it's IPv4
	if (data[0] >> 4) != 4 {
		return false
	}

	// Check if protocol is UDP (17)
	return data[9] == 17
}

// IsTCPPacket checks if the IP packet contains TCP payload
func IsTCPPacket(data []byte) bool {
	if len(data) < 20 {
		return false
	}

	// Check if it's IPv4
	if (data[0] >> 4) != 4 {
		return false
	}

	// Check if protocol is TCP (6)
	return data[9] == 6
}
