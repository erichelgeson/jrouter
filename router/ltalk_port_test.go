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
	"net"
	"testing"

	"github.com/sfiera/multitalk/pkg/ddp"
)

func TestBuildLocalIPSet(t *testing.T) {
	ips, err := buildLocalIPSet()
	if err != nil {
		t.Fatalf("buildLocalIPSet() error = %v", err)
	}
	// Loopback (127.0.0.1) should always be present
	loopback := [4]byte{127, 0, 0, 1}
	if _, ok := ips[loopback]; !ok {
		t.Errorf("buildLocalIPSet() missing loopback 127.0.0.1, got %v", ips)
	}
}

func TestIsOwnPacket(t *testing.T) {
	port := &LocalTalkPort{
		senderID: [4]byte{0x00, 0x00, 0x12, 0x34},
		localIPs: map[[4]byte]struct{}{
			{127, 0, 0, 1}: {},
			{10, 0, 0, 5}:  {},
		},
	}

	tests := []struct {
		name     string
		senderID []byte
		srcIP    string
		want     bool
	}{
		{
			name:     "matching ID and local IP",
			senderID: []byte{0x00, 0x00, 0x12, 0x34},
			srcIP:    "127.0.0.1",
			want:     true,
		},
		{
			name:     "matching ID and different local IP",
			senderID: []byte{0x00, 0x00, 0x12, 0x34},
			srcIP:    "10.0.0.5",
			want:     true,
		},
		{
			name:     "matching ID but remote IP",
			senderID: []byte{0x00, 0x00, 0x12, 0x34},
			srcIP:    "192.168.1.100",
			want:     false,
		},
		{
			name:     "non-matching ID with local IP",
			senderID: []byte{0x00, 0x00, 0x56, 0x78},
			srcIP:    "127.0.0.1",
			want:     false,
		},
		{
			name:     "non-matching ID with remote IP",
			senderID: []byte{0x00, 0x00, 0x56, 0x78},
			srcIP:    "192.168.1.100",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srcAddr := &net.UDPAddr{IP: net.ParseIP(tt.srcIP), Port: LTOUDPPort}
			got := port.isOwnPacket(tt.senderID, srcAddr)
			if got != tt.want {
				t.Errorf("isOwnPacket() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBroadcastDoesNotMutatePacket(t *testing.T) {
	// Create a minimal port with enough state for Broadcast to work
	// We need a conn to write to—use a UDP connection to localhost that we can discard
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP error = %v", err)
	}
	defer conn.Close()

	port := &LocalTalkPort{
		conn:          conn,
		multicastAddr: &net.UDPAddr{IP: net.ParseIP(LTOUDPMulticastGroup), Port: LTOUDPPort},
		network:       42,
		myNode:        10,
		nodeAcquired:  true,
	}

	pkt := &ddp.ExtPacket{
		ExtHeader: ddp.ExtHeader{
			DstNet:    0,
			DstNode:   5, // Not broadcast
			SrcNet:    42,
			SrcNode:   10,
			DstSocket: 2,
			SrcSocket: 2,
			Proto:     ddp.ProtoNBP,
		},
		Data: []byte{0x01, 0x02, 0x03},
	}

	origDstNode := pkt.DstNode

	// Broadcast may fail (no multicast route) but that's OK—we're testing mutation
	_ = port.Broadcast(pkt)

	if pkt.DstNode != origDstNode {
		t.Errorf("Broadcast mutated pkt.DstNode: got %d, want %d", pkt.DstNode, origDstNode)
	}
}
