// Copyright (c) 2019, Adel "0x4d31" Karimi.
// All rights reserved.
// Licensed under the BSD 3-Clause license.
// For full license text, see the LICENSE file in the repo root
// or https://opensource.org/licenses/BSD-3-Clause

package quick

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/hkdf"
)

type CHLO struct {
	QUICMessage
	MessageAuthHash []byte
	FrameType       byte
	FtStream        bool
	FtFIN           bool
	FtDataLength    uint8
	FtOffsetLength  uint8
	FtStreamLength  uint8
	StreamID        uint8
	DataLength      uint16
	Tag             string
	TagNumber       uint16
	TagValues       map[string]string
	TagsInOrder     []string

	// non exported
	dcil           uint8
	scil           uint8
	destinationCID []byte
	sourceCID      []byte
	token          []byte
	length         uint64
	frame          []byte
	secret         []byte
}

func (ch CHLO) String() string {
	str := fmt.Sprintf("Public Flags: %x\n", ch.PublicFlags)
	str += fmt.Sprintf("CID: %x\n", ch.CID)
	str += fmt.Sprintf("Version: %s\n", ch.Version)
	str += fmt.Sprintf("Packet Number: %d\n", ch.PacketNumber)
	str += fmt.Sprintf("Message Authentication Hash: %x\n", ch.MessageAuthHash)
	str += fmt.Sprintf("Frame Type: %x\n", ch.FrameType)
	str += fmt.Sprintf("Stream ID: %d\n", ch.StreamID)
	str += fmt.Sprintf("Data Length: %d\n", ch.DataLength)
	str += fmt.Sprintf("Tag: %s\n", ch.Tag)
	str += fmt.Sprintf("Tag Number: %d\n", ch.TagNumber)
	str += fmt.Sprintf("SNI: %q\n", ch.TagValues["SNI"])
	str += fmt.Sprintf("UAID: %q\n", ch.TagValues["UAID"])
	str += fmt.Sprintf("Tags in Order: %q\n", ch.TagsInOrder)
	str += fmt.Sprintln("Tag Values:", ch.TagValues)
	return str
}

// ATQ draft-27
func varint(p *bytes.Reader) uint64 {
	n, _ := p.ReadByte()
	l := uint8(n >> 6)
	switch l {
	case 0x00:
		return uint64(n & 0x3f)
	case 0x01:
		n2, _ := p.ReadByte()
		return uint64(binary.BigEndian.Uint16([]byte{n & 0x3f, n2}))
	case 0x02:
		n2 := make([]byte, 2, 2)
		p.Read(n2)
		return uint64(binary.BigEndian.Uint32([]byte{n & 0x3f, n2[0], n2[1]}))
	case 0x03:
		n2 := make([]byte, 3, 3)
		p.Read(n2)
		return binary.BigEndian.Uint64([]byte{n & 0x3f, n2[0], n2[1], n2[2]})
	}
	return 0
}

var salt = []byte{
	0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a,
	0x11, 0xa7, 0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65,
	0xbe, 0xf9, 0xf5, 0x02,
}

var label = []byte("client in")

func (ch *CHLO) DecodeIETF(payload *bytes.Reader) error {
	ch.Version = "IETF"
	ch.dcil, _ = payload.ReadByte()
	ch.destinationCID = make([]byte, ch.dcil, ch.dcil)
	binary.Read(payload, binary.BigEndian, &ch.destinationCID)
	ch.scil, _ = payload.ReadByte()
	ch.sourceCID = make([]byte, ch.scil, ch.scil)
	binary.Read(payload, binary.BigEndian, &ch.sourceCID)
	ch.token = make([]byte, varint(payload))
	n, _ := payload.Read(ch.token)
	if n != 0 {
		return ErrWrongType
	}
	ch.length = varint(payload)
	ch.frame = make([]byte, ch.length, ch.length)
	payload.Read(ch.frame)

	ch.secret = hkdf.Extract(sha256.New, ch.destinationCID, salt)
	context := []byte{}
	var hkdfLabel cryptobyte.Builder
	hkdfLabel.AddUint16(uint16(32))
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte("tls13 "))
		b.AddBytes([]byte(label))
	})
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(context)
	})
	out := make([]byte, 32)
	n, err := hkdf.Expand(sha256.New, ch.secret, hkdfLabel.BytesOrPanic()).Read(out)
	if err != nil || n != 32 {
		return errors.New("BAD EXPANSION")
	}
	fmt.Printf("%x\n", out)
	return nil
}

func (ch *CHLO) DecodeCHLO(payload []byte) error {
	ch.Raw = payload
	if binary.BigEndian.Uint32(payload[1:5])&0xffffff00 == 0xff000000 &&
		payload[0]&0x30 == 0x00 {
		err := ch.DecodeIETF(bytes.NewReader(payload[5:]))
		return err
	}
	if !(bytes.Contains(payload, []byte("CHLO"))) {
		return ErrWrongType
	}
	// Public Flags
	ch.PublicFlags = payload[0]
	ch.PfVersion = payload[0]&0x01 != 0              // Version
	ch.PfReset = payload[0]&0x02 != 0                // Reset
	ch.PfDivNonce = payload[0]&0x04 != 0             // Diversification Nonce
	ch.PfCIDLen = payload[0]&0x08 != 0               // CID Length
	ch.PfPacketNumLen = (payload[0] & 0x30 >> 4) + 1 // Packet Number Length in bytes
	ch.PfMultipath = payload[0]&0x40 != 0            // Multipath
	ch.PfReserved = payload[0]&0x80 != 0             // Reserved
	if ch.PublicFlags == 0 {
		return ErrBadPFlags
	}
	hs := payload[1:]
	// CID Length
	if ch.PfCIDLen {
		ch.CID = hs[0:8]
		hs = hs[8:]
	}
	// Version
	if ch.PfVersion {
		ch.Version = string(hs[0:4])
		hs = hs[4:]
	}
	// Packet Number Length
	switch ch.PfPacketNumLen {
	case 1:
		ch.PacketNumber = uint(hs[0])
	case 2:
		ch.PacketNumber = uint(binary.BigEndian.Uint16(hs[0:2]))
	case 3:
		ch.PacketNumber = (uint(hs[0]) << 16) | (uint(hs[1]) << 8) | uint(hs[2])
	}
	hs = hs[ch.PfPacketNumLen:]
	// Message Authentication Hash
	ch.MessageAuthHash = hs[0:12]
	// Frame Type
	ch.FrameType = hs[12]
	ch.FtStream = hs[12]&0x80 != 0             // STREAM
	ch.FtFIN = hs[12]&0x40 != 0                // FIN
	ch.FtDataLength = (hs[12] & 0x20 >> 5) + 1 // Data Length in bytes
	ch.FtOffsetLength = hs[12] & 0x1C >> 2     // Offset Length
	ch.FtStreamLength = hs[12] & 0x3           // Stream Length
	ch.StreamID = uint8(hs[13])                // Stream ID
	// Data Length
	if ch.FtDataLength == 2 {
		ch.DataLength = binary.BigEndian.Uint16(hs[14:16])
	} else {
		return ErrBadFtDLen
	}
	if len(hs[16:]) < int(ch.DataLength) {
		return ErrBadLength
	}
	// Tag: CHLO (Client Hello)
	ch.Tag = string(hs[16:20])
	if ch.Tag != "CHLO" {
		return ErrWrongType
	}
	// Tag Number
	ch.TagNumber = binary.LittleEndian.Uint16(hs[20:22])
	hs = hs[24:] // Padding: 0000
	if len(hs) < 2 {
		return ErrBadLength
	}
	// Tag/Values
	ch.TagValues = make(map[string]string)
	TagsOffsetEnd := make(map[string]uint32)
	// Extract tags offset end
	for i := 0; i < int(ch.TagNumber); i++ {
		var TagName string
		TempTag := hs[0:4]
		if TempTag[3] == 0 {
			TagName = string(TempTag[0:3])
		} else {
			TagName = string(TempTag[0:4])
		}
		TagsOffsetEnd[TagName] = binary.LittleEndian.Uint32(hs[4:8])
		ch.TagsInOrder = append(ch.TagsInOrder, TagName)
		hs = hs[8:]
	}
	for i, tag := range ch.TagsInOrder {
		// Calculate the tag length
		var TagLen uint32
		if i == 0 {
			TagLen = TagsOffsetEnd[tag]
		} else {
			TagLen = TagsOffsetEnd[tag] - TagsOffsetEnd[ch.TagsInOrder[i-1]]
		}
		// Extract the intended tag/values
		switch tag {
		case "SNI", "UAID", "AEAD", "KEXS", "VER", "PDMD", "COPT":
			ch.TagValues[tag] = string(hs[0:TagLen])
		case "PAD": //do nothing
		default:
			ch.TagValues[tag] = hex.EncodeToString(hs[0:TagLen])
		}
		hs = hs[TagLen:]
	}

	return nil
}
