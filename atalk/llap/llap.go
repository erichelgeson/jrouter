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

// Package llap implements LLAP (LocalTalk Link Access Protocol) frame handling
// for LocalTalk over UDP (LTOU).
package llap

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/sfiera/multitalk/pkg/ddp"
)

// LLAP frame types
const (
	TypeShortDDP = 0x01 // Short DDP header (same-network traffic)
	TypeLongDDP  = 0x02 // Long DDP header (routed traffic)
	TypeENQ      = 0x81 // Enquiry (node address acquisition)
	TypeACK      = 0x82 // Acknowledgment (node address acquisition)
	TypeRTS      = 0x84 // Request to Send (collision avoidance) - DO NOT transmit over UDP
	TypeCTS      = 0x85 // Clear to Send (collision avoidance) - DO NOT transmit over UDP
)

// Frame header size constants
const (
	FrameHeaderSize    = 3  // dest node + src node + type
	ShortDDPHeaderSize = 5  // length (2) + dst socket + src socket + proto
	LongDDPHeaderSize  = 13 // hop+len (2) + cksum (2) + dst net (2) + src net (2) + dst node + src node + dst socket + src socket + proto
)

// MaxDataLength is the maximum DDP data payload size
const MaxDataLength = 586

// Errors
var (
	ErrFrameTooShort     = errors.New("llap: frame too short")
	ErrInvalidLLAPType   = errors.New("llap: invalid LLAP type")
	ErrShortDDPTooShort  = errors.New("llap: short DDP data too short")
	ErrLongDDPTooShort   = errors.New("llap: long DDP data too short")
	ErrInvalidLength     = errors.New("llap: invalid length field")
	ErrInvalidShortDDP   = errors.New("llap: invalid short DDP header bits")
	ErrInvalidLongDDP    = errors.New("llap: invalid long DDP header bits")
)

// Frame represents an LLAP frame.
type Frame struct {
	DstNode ddp.Node
	SrcNode ddp.Node
	Type    byte
	Data    []byte // Payload (DDP header + data for Type 0x01/0x02, empty for ENQ/ACK)
}

// Unmarshal parses an LLAP frame from bytes.
func Unmarshal(data []byte) (*Frame, error) {
	if len(data) < FrameHeaderSize {
		return nil, ErrFrameTooShort
	}
	return &Frame{
		DstNode: ddp.Node(data[0]),
		SrcNode: ddp.Node(data[1]),
		Type:    data[2],
		Data:    data[FrameHeaderSize:],
	}, nil
}

// Marshal serializes an LLAP frame for transmission.
func (f *Frame) Marshal() []byte {
	out := make([]byte, FrameHeaderSize+len(f.Data))
	out[0] = byte(f.DstNode)
	out[1] = byte(f.SrcNode)
	out[2] = f.Type
	copy(out[FrameHeaderSize:], f.Data)
	return out
}

// ShortDDPToExtPacket converts a short DDP frame to an extended DDP packet.
// The network parameter specifies the local network number to use for
// src/dst network fields (short DDP doesn't include network numbers).
func ShortDDPToExtPacket(frame *Frame, network ddp.Network) (*ddp.ExtPacket, error) {
	if frame.Type != TypeShortDDP {
		return nil, fmt.Errorf("llap: expected short DDP type 0x01, got 0x%02x", frame.Type)
	}
	data := frame.Data
	if len(data) < ShortDDPHeaderSize {
		return nil, ErrShortDDPTooShort
	}

	// Short DDP header format:
	// Byte 0: top 6 bits must be 0, bottom 2 bits are high bits of length
	// Byte 1: low 8 bits of length
	// Byte 2: destination socket
	// Byte 3: source socket
	// Byte 4: DDP type (protocol)
	first := data[0]
	second := data[1]

	if first&0xFC != 0 {
		return nil, ErrInvalidShortDDP
	}

	length := int(first&0x03)<<8 | int(second)
	if length < ShortDDPHeaderSize || length > ShortDDPHeaderSize+MaxDataLength {
		return nil, fmt.Errorf("%w: %d", ErrInvalidLength, length)
	}
	if length != len(data) {
		return nil, fmt.Errorf("%w: header says %d, got %d", ErrInvalidLength, length, len(data))
	}

	pkt := &ddp.ExtPacket{
		ExtHeader: ddp.ExtHeader{
			// Size field: length including DDP extended header (13 bytes)
			// For short->extended conversion, payload size stays the same
			Size:      uint16(LongDDPHeaderSize + len(data) - ShortDDPHeaderSize),
			Cksum:     0, // No checksum for locally-sourced packets
			DstNet:    network,
			SrcNet:    network,
			DstNode:   frame.DstNode,
			SrcNode:   frame.SrcNode,
			DstSocket: ddp.Socket(data[2]),
			SrcSocket: ddp.Socket(data[3]),
			Proto:     data[4],
		},
		Data: data[ShortDDPHeaderSize:],
	}
	return pkt, nil
}

// LongDDPToExtPacket converts a long DDP frame to an extended DDP packet.
func LongDDPToExtPacket(frame *Frame) (*ddp.ExtPacket, error) {
	if frame.Type != TypeLongDDP {
		return nil, fmt.Errorf("llap: expected long DDP type 0x02, got 0x%02x", frame.Type)
	}
	data := frame.Data
	if len(data) < LongDDPHeaderSize {
		return nil, ErrLongDDPTooShort
	}

	// Long DDP header format:
	// Bytes 0-1: hop count (4 bits) + length (10 bits)
	// Bytes 2-3: checksum
	// Bytes 4-5: destination network
	// Bytes 6-7: source network
	// Byte 8: destination node
	// Byte 9: source node
	// Byte 10: destination socket
	// Byte 11: source socket
	// Byte 12: DDP type (protocol)
	first := data[0]
	second := data[1]

	if first&0xC0 != 0 {
		return nil, ErrInvalidLongDDP
	}

	hopCount := (first & 0x3C) >> 2
	length := int(first&0x03)<<8 | int(second)

	if length < LongDDPHeaderSize || length > LongDDPHeaderSize+MaxDataLength {
		return nil, fmt.Errorf("%w: %d", ErrInvalidLength, length)
	}
	if length != len(data) {
		return nil, fmt.Errorf("%w: header says %d, got %d", ErrInvalidLength, length, len(data))
	}

	pkt := &ddp.ExtPacket{
		ExtHeader: ddp.ExtHeader{
			Size:      uint16(length) | (uint16(hopCount) << 10),
			Cksum:     binary.BigEndian.Uint16(data[2:4]),
			DstNet:    ddp.Network(binary.BigEndian.Uint16(data[4:6])),
			SrcNet:    ddp.Network(binary.BigEndian.Uint16(data[6:8])),
			DstNode:   ddp.Node(data[8]),
			SrcNode:   ddp.Node(data[9]),
			DstSocket: ddp.Socket(data[10]),
			SrcSocket: ddp.Socket(data[11]),
			Proto:     data[12],
		},
		Data: data[LongDDPHeaderSize:],
	}
	return pkt, nil
}

// ExtPacketToShortDDP converts an extended DDP packet to short DDP format.
// This should only be used for same-network traffic where src and dst
// are on the local network.
func ExtPacketToShortDDP(pkt *ddp.ExtPacket, srcNode ddp.Node) *Frame {
	dataLen := len(pkt.Data)
	length := ShortDDPHeaderSize + dataLen

	data := make([]byte, length)
	data[0] = byte((length >> 8) & 0x03)
	data[1] = byte(length & 0xFF)
	data[2] = byte(pkt.DstSocket)
	data[3] = byte(pkt.SrcSocket)
	data[4] = byte(pkt.Proto)
	copy(data[ShortDDPHeaderSize:], pkt.Data)

	return &Frame{
		DstNode: pkt.DstNode,
		SrcNode: srcNode,
		Type:    TypeShortDDP,
		Data:    data,
	}
}

// ExtPacketToLongDDP converts an extended DDP packet to long DDP format.
// This should be used for routed traffic.
// Note: The checksum is always set to 0 (no checksum) because:
// 1. Original checksums become invalid after routing (hop count changes)
// 2. DDP spec requires receivers to accept checksum=0
// 3. LocalTalk is a different physical network with different error characteristics
func ExtPacketToLongDDP(pkt *ddp.ExtPacket, srcNode ddp.Node) *Frame {
	dataLen := len(pkt.Data)
	length := LongDDPHeaderSize + dataLen
	hopCount := (pkt.Size & 0x3C00) >> 10

	data := make([]byte, length)
	data[0] = byte(hopCount<<2) | byte((length>>8)&0x03)
	data[1] = byte(length & 0xFF)
	// Checksum is set to 0 - bytes 2-3 are already zero from make()
	binary.BigEndian.PutUint16(data[4:6], uint16(pkt.DstNet))
	binary.BigEndian.PutUint16(data[6:8], uint16(pkt.SrcNet))
	data[8] = byte(pkt.DstNode)
	data[9] = byte(pkt.SrcNode)
	data[10] = byte(pkt.DstSocket)
	data[11] = byte(pkt.SrcSocket)
	data[12] = byte(pkt.Proto)
	copy(data[LongDDPHeaderSize:], pkt.Data)

	return &Frame{
		DstNode: pkt.DstNode,
		SrcNode: srcNode,
		Type:    TypeLongDDP,
		Data:    data,
	}
}

// ExtPacketToFrame converts an extended DDP packet to an LLAP frame,
// choosing short or long DDP format based on whether the packet is
// local (same network) or routed.
func ExtPacketToFrame(pkt *ddp.ExtPacket, localNet ddp.Network, srcNode ddp.Node) *Frame {
	// Use short DDP for same-network traffic
	// Short DDP is used when both src and dst networks are the local network (or 0)
	srcLocal := pkt.SrcNet == localNet || pkt.SrcNet == 0
	dstLocal := pkt.DstNet == localNet || pkt.DstNet == 0

	if srcLocal && dstLocal {
		return ExtPacketToShortDDP(pkt, srcNode)
	}
	return ExtPacketToLongDDP(pkt, srcNode)
}

// NewENQFrame creates an ENQ frame for node address acquisition.
// The node parameter is the node address being enquired about.
func NewENQFrame(node ddp.Node) *Frame {
	return &Frame{
		DstNode: node,
		SrcNode: node,
		Type:    TypeENQ,
		Data:    nil,
	}
}

// NewACKFrame creates an ACK frame in response to an ENQ.
// The node parameter is the node address being acknowledged.
func NewACKFrame(node ddp.Node) *Frame {
	return &Frame{
		DstNode: node,
		SrcNode: node,
		Type:    TypeACK,
		Data:    nil,
	}
}
