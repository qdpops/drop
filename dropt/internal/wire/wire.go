// Package wire implements the DROP HTTP-transport framing and cryptography.
//
// The session layer is transport-agnostic; here it rides ordinary HTTP
// request/response bodies (see cmd/server, cmd/client). Everything is
// stdlib-only so the binaries build offline and have no supply chain.
package wire

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

// ---------------------------------------------------------------------------
// Frames
//
// A logical stream is one SOCKS connection. Many streams are multiplexed over
// the single HTTP channel. On the wire a frame is:
//
//	stream(4) | type(1) | len(2) | payload(len)
//
// Batches of frames are concatenated, then the whole batch is sealed and
// carried as one HTTP body.
// ---------------------------------------------------------------------------

const (
	FrameSYN  byte = 1 // open stream; payload = "host:port"
	FrameData byte = 2 // stream bytes
	FrameFIN  byte = 3 // stream finished (graceful)
	FrameRST  byte = 4 // stream aborted
)

// MaxData is the largest payload carried in a single Data frame.
const MaxData = 16384

type Frame struct {
	Stream uint32
	Type   byte
	Data   []byte
}

func MarshalFrames(fs []Frame) []byte {
	out := make([]byte, 0, 64)
	var hdr [7]byte
	for _, f := range fs {
		binary.BigEndian.PutUint32(hdr[0:4], f.Stream)
		hdr[4] = f.Type
		binary.BigEndian.PutUint16(hdr[5:7], uint16(len(f.Data)))
		out = append(out, hdr[:]...)
		out = append(out, f.Data...)
	}
	return out
}

func UnmarshalFrames(b []byte) ([]Frame, error) {
	var fs []Frame
	for len(b) > 0 {
		if len(b) < 7 {
			return nil, errors.New("wire: short frame header")
		}
		stream := binary.BigEndian.Uint32(b[0:4])
		typ := b[4]
		n := int(binary.BigEndian.Uint16(b[5:7]))
		b = b[7:]
		if len(b) < n {
			return nil, errors.New("wire: short frame body")
		}
		d := make([]byte, n)
		copy(d, b[:n])
		b = b[n:]
		fs = append(fs, Frame{Stream: stream, Type: typ, Data: d})
	}
	return fs, nil
}

// ---------------------------------------------------------------------------
// Batch header
//
// Every sealed HTTP body now starts with an 8-byte big-endian sequence number
// prepended to the marshalled frame payload:
//
//	seq(8) | frame... frame...
//
// seq numbers are assigned independently on each direction (c→s and s→c).
// The handshake batch uses seq=0 on both directions; the window layer starts
// at seq=1 for all subsequent traffic.
// ---------------------------------------------------------------------------

// BatchHeaderSize is the byte length of the sequence prefix.
const BatchHeaderSize = 8

// MarshalBatch prepends seq to the marshalled frames.
func MarshalBatch(seq uint64, fs []Frame) []byte {
	var hdr [BatchHeaderSize]byte
	binary.BigEndian.PutUint64(hdr[:], seq)
	return append(hdr[:], MarshalFrames(fs)...)
}

// UnmarshalBatch splits a batch plaintext into its sequence number and frames.
func UnmarshalBatch(b []byte) (seq uint64, fs []Frame, err error) {
	if len(b) < BatchHeaderSize {
		return 0, nil, errors.New("wire: short batch header")
	}
	seq = binary.BigEndian.Uint64(b[:BatchHeaderSize])
	fs, err = UnmarshalFrames(b[BatchHeaderSize:])
	return
}

// ---------------------------------------------------------------------------
// Cryptography
//
// Handshake (Noise_N-style):
//   - The server holds a long-term X25519 static key. Its public half ships
//     inside the client config.
//   - The client generates an ephemeral X25519 key per session and performs
//     ECDH against the server static key.
//   - The pre-shared key (PSK) is folded in as the HKDF salt. Without the PSK
//     an attacker cannot derive the working keys, so the AEAD open fails and
//     the server can treat the request as an ordinary web visitor
//     (probe resistance).
//
// This gives confidentiality, integrity and probe resistance. It does NOT give
// forward secrecy against server-static-key compromise; upgrading to an
// ephemeral-ephemeral Noise_XX/IK handshake is the documented next step.
// ---------------------------------------------------------------------------

func GenerateStatic() (*ecdh.PrivateKey, error) { return ecdh.X25519().GenerateKey(rand.Reader) }
func PrivFromBytes(b []byte) (*ecdh.PrivateKey, error) {
	return ecdh.X25519().NewPrivateKey(b)
}
func PubFromBytes(b []byte) (*ecdh.PublicKey, error) {
	return ecdh.X25519().NewPublicKey(b)
}

// Cipher is one direction of an authenticated channel. AES-256-GCM with a
// random 96-bit nonce prepended to each record. Each session derives unique
// keys, so random nonces are collision-safe for realistic message volumes.
type Cipher struct{ aead cipher.AEAD }

func newCipher(key []byte) (*Cipher, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: a}, nil
}

func (c *Cipher) Seal(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	out := make([]byte, len(nonce))
	copy(out, nonce)
	return c.aead.Seal(out, nonce, plaintext, nil), nil
}

func (c *Cipher) Open(blob []byte) ([]byte, error) {
	ns := c.aead.NonceSize()
	if len(blob) < ns+16 {
		return nil, errors.New("wire: short ciphertext")
	}
	return c.aead.Open(nil, blob[:ns], blob[ns:], nil)
}

func hkdfExtract(salt, ikm []byte) []byte {
	m := hmac.New(sha256.New, salt)
	m.Write(ikm)
	return m.Sum(nil)
}

func hkdfExpand(prk []byte, info string, n int) []byte {
	var out, t []byte
	var ctr byte = 1
	for len(out) < n {
		m := hmac.New(sha256.New, prk)
		m.Write(t)
		m.Write([]byte(info))
		m.Write([]byte{ctr})
		t = m.Sum(nil)
		out = append(out, t...)
		ctr++
	}
	return out[:n]
}

func deriveCiphers(shared, psk []byte) (c2s, s2c *Cipher, err error) {
	prk := hkdfExtract(psk, shared)
	if c2s, err = newCipher(hkdfExpand(prk, "drop c2s v1", 32)); err != nil {
		return
	}
	if s2c, err = newCipher(hkdfExpand(prk, "drop s2c v1", 32)); err != nil {
		return
	}
	return
}

// ServerSession derives the channel keys on the server side.
func ServerSession(static *ecdh.PrivateKey, clientEph *ecdh.PublicKey, psk []byte) (c2s, s2c *Cipher, err error) {
	shared, err := static.ECDH(clientEph)
	if err != nil {
		return nil, nil, err
	}
	return deriveCiphers(shared, psk)
}

// ClientSession derives the channel keys on the client side.
func ClientSession(eph *ecdh.PrivateKey, serverStatic *ecdh.PublicKey, psk []byte) (c2s, s2c *Cipher, err error) {
	shared, err := eph.ECDH(serverStatic)
	if err != nil {
		return nil, nil, err
	}
	return deriveCiphers(shared, psk)
}
