package quick

import (
	"crypto/aes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/hkdf"

	"github.com/marten-seemann/qtls"
)

var salt = []byte{
	0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a,
	0x11, 0xa7, 0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65,
	0xbe, 0xf9, 0xf5, 0x02,
}

func (c *CHLO) decodeIETF(p []byte) error {
	defer func() {
		if r := recover(); r != nil {
			// print("maloformed err")
		}
	}()
	c.Raw = p[:]
	c.TagValues = make(map[string]string)
	i := 0
	sampleOffset := 7
	c.Version = fmt.Sprintf("%x", p[1:5])
	i += 5
	dcil, l := varint(p[i:])
	i += l
	sampleOffset += int(dcil)
	dcid := make([]byte, dcil)
	copy(dcid, p[i:])
	c.CID = dcid
	i += int(dcil)
	scil, l := varint(p[i:])
	i += l
	sampleOffset += int(scil)
	scid := make([]byte, scil)
	copy(scid, p[i:])
	i += int(scil)
	tl, l := varint(p[i:])
	sampleOffset += l + int(tl)
	i += l
	// token neccessary ??
	// token := make([]byte, int(tl))
	// copy(token, p[i:i+int(tl)])
	// fmt.Printf("token %x\n", token)
	i += int(tl)
	_, l = varint(p[i:])
	sampleOffset += l + 4
	i += l
	sample := p[sampleOffset : sampleOffset+16]
	initialSecret := hkdf.Extract(sha256.New, dcid, salt)
	clientSc := hkdfExpandLabel([]byte{}, []byte("client in"), initialSecret, 32)
	headerPr := hkdfExpandLabel([]byte{}, []byte("quic hp"), clientSc, 16)
	block, err := aes.NewCipher(headerPr)
	if err != nil {
		return err
	}
	mask := make([]byte, block.BlockSize())
	block.Encrypt(mask, sample)
	_pnlen := int((p[0] ^ mask[0]) & 0x0f)
	_pn := make([]byte, 4)
	for m := 0; m <= _pnlen; m++ {
		_pn[m] = p[sampleOffset-4+m] ^ mask[1+m]
	}
	pn := binary.BigEndian.Uint32(_pn)
	c.PacketNumber = uint(pn)
	iv := hkdfExpandLabel([]byte{}, []byte("quic iv"), clientSc, 12)
	key := hkdfExpandLabel([]byte{}, []byte("quic key"), clientSc, 16)
	aead := qtls.AEADAESGCMTLS13(key, iv)
	nonceBuf := make([]byte, aead.NonceSize())
	binary.BigEndian.PutUint64(nonceBuf[len(nonceBuf)-8:], uint64(pn))
	dec := aead.Seal(nil, nonceBuf, p[sampleOffset-(3-_pnlen):], p[:sampleOffset])
	c.decodeCryptoFrame(dec[:len(p[sampleOffset-(3-_pnlen):])-16])
	return nil
}

func hkdfExpandLabel(context, label, secret []byte, size int) []byte {
	cb := cryptobyte.Builder{}
	cb.AddUint16(uint16(size))
	cb.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte("tls13 "))
		b.AddBytes([]byte(label))
	})
	cb.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(context)
	})
	out := make([]byte, size)
	_, _ = hkdf.Expand(sha256.New, secret, cb.BytesOrPanic()).Read(out)
	return out
}

// ATQ draft-27

func varint(p []byte) (uint64, int) {
	n := p[0]
	l := uint8(n >> 6)
	switch l {
	case 0x00:
		return uint64(n & 0x3f), 1
	case 0x01:
		n2 := p[1]
		return uint64(binary.BigEndian.Uint16([]byte{n & 0x3f, n2})), 2
	case 0x02:
		n2 := []byte{p[1], p[2]}
		return uint64(binary.BigEndian.Uint32([]byte{n & 0x3f, n2[0], n2[1]})), 3
	case 0x03:
		n2 := []byte{p[1], p[2], p[3]}
		return binary.BigEndian.Uint64([]byte{n & 0x3f, n2[0], n2[1], n2[2]}), 4
	}
	return 0, 0
}

func (c *CHLO) decodeTLSHandshake(p []byte) {
	if p[0] == 0x01 {
		c.TagValues["TLS min version"] = fmt.Sprintf("%x", p[4])
		c.TagValues["TLS max version"] = fmt.Sprintf("%x", p[5])
		_, sidlen := varint(p[6+32:])
		l := binary.BigEndian.Uint16([]byte{p[6+32+sidlen], p[6+32+sidlen+1]})
		i := 6 + 32 + sidlen + 1
		for k := 0; k < int(l); k += 2 {
			c.TagsInOrder = append(c.TagsInOrder, nameCipher(p[i+k+1], p[i+k+2]))
		}
		i += int(l) + 1
		i += 2
		extlen := binary.BigEndian.Uint16([]byte{p[i], p[1+i]})
		i += 2

		for k := i; k < i+int(extlen); k += 0 {
			ty := binary.BigEndian.Uint16([]byte{p[k], p[1+k]})
			k += 2
			l := binary.BigEndian.Uint16([]byte{p[k], p[1+k]})
			k += 2
			if ty == 0x00 {
				t := k + 2
				if p[t] == 0x00 {
					c.TagValues["SNI"] = string(p[t+3 : k+int(l)])
				}
			}
			k += int(l)
		}
	}
}

func nameCipher(f, s byte) string {
	switch f {
	case 0x13:
		switch s {
		case 0x01:
			return "TLS_AES_128_GCM_SHA384"
		case 0x02:
			return "TLS_AES_256_GCM_SHA256"
		case 0x03:
			return "TLS_CHACHA20_POLY1305_SHA256"
		case 0x04:
			return "TLS_AES_128_CCM_SHA256"
		case 0x05:
			return "TLS_AES_128_CCM_8_SHA256"
		default:
			return fmt.Sprintf("urecognized id %x", s)
		}
	default:
		return "invaild value"
	}
}

func (c *CHLO) decodeCryptoFrame(p []byte) {
	size := len(p)
	i := 0
	for i < size {
		if p[i] == 0x06 {
			offset, l := varint(p[i+1:])
			i += l
			length, l := varint(p[i+1:])
			c.decodeTLSHandshake(p[i+1+int(offset)+l:])
			i += l + int(offset) + int(length)
		}
		i++
	}
}
