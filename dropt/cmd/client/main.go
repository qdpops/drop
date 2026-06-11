// Command client is the DROP transport client. It runs a local SOCKS5 proxy;
// every SOCKS connection becomes a multiplexed stream carried to the server
// over ordinary-looking HTTPS requests (POST /api/events for upstream, a
// long-poll GET /api/updates for downstream). Point your VPN/app SOCKS at it.
package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dropt/internal/wire"
)

const (
	userAgent    = "Notedeck/3.2 (sync)"
	pollTimeout  = 25 * time.Second
	postTimeout  = 30 * time.Second
	batchMax     = 256
	batchWindow  = 5 * time.Millisecond
	windowSize   = 8        // parallel upstream lanes and concurrent downstream polls
	maxBatchBody = 768<<10  // stay well under server's 1 MiB maxBody limit
)

// ---------------------------------------------------------------------------
// Downstream reorder buffer
//
// windowSize goroutines each drive an independent long-poll (or receive an
// ack from a POST lane). Their responses arrive out of order but carry
// monotone seq numbers assigned by the server. downReorderBuf holds
// out-of-order batches and signals the dispatcher when the next expected seq
// has arrived so frames are always dispatched in the original server order.
// ---------------------------------------------------------------------------

type downReorderBuf struct {
	mu      sync.Mutex
	nextSeq uint64
	pending map[uint64][]wire.Frame
	ready   chan struct{} // capacity-1; pulsed when nextSeq arrives
}

func (rb *downReorderBuf) add(seq uint64, fs []wire.Frame) {
	rb.mu.Lock()
	rb.pending[seq] = fs
	_, has := rb.pending[rb.nextSeq]
	rb.mu.Unlock()
	if has {
		select {
		case rb.ready <- struct{}{}:
		default:
		}
	}
}

// drain calls dispatch for every in-order frame, advancing nextSeq.
// Called only from the single dispatcher goroutine.
func (rb *downReorderBuf) drain(dispatch func(wire.Frame)) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	for {
		fs, ok := rb.pending[rb.nextSeq]
		if !ok {
			return
		}
		delete(rb.pending, rb.nextSeq)
		rb.nextSeq++
		rb.mu.Unlock()
		for _, f := range fs {
			dispatch(f)
		}
		rb.mu.Lock()
	}
}

// ---------------------------------------------------------------------------
// Per-stream and per-session state
// ---------------------------------------------------------------------------

type cstream struct {
	conn net.Conn
}

type csession struct {
	c2s, s2c *wire.Cipher
	sid      string

	outQ chan wire.Frame

	mu      sync.Mutex
	streams map[uint32]*cstream
	nextID  uint32

	downBuf downReorderBuf

	dead     chan struct{}
	deadOnce sync.Once
}

func (s *csession) die() { s.deadOnce.Do(func() { close(s.dead) }) }

func (s *csession) addStream(conn net.Conn) (uint32, *cstream) {
	id := atomic.AddUint32(&s.nextID, 1)
	cs := &cstream{conn: conn}
	s.mu.Lock()
	s.streams[id] = cs
	s.mu.Unlock()
	return id, cs
}

func (s *csession) dropStream(id uint32) {
	s.mu.Lock()
	cs := s.streams[id]
	delete(s.streams, id)
	s.mu.Unlock()
	if cs != nil {
		cs.conn.Close()
	}
}

func (s *csession) dispatch(f wire.Frame) {
	s.mu.Lock()
	cs := s.streams[f.Stream]
	s.mu.Unlock()
	switch f.Type {
	case wire.FrameData:
		if cs != nil {
			cs.conn.Write(f.Data)
		}
	case wire.FrameFIN, wire.FrameRST:
		s.dropStream(f.Stream)
	}
}

func (s *csession) teardown() {
	s.mu.Lock()
	for _, cs := range s.streams {
		cs.conn.Close()
	}
	s.streams = make(map[uint32]*cstream)
	s.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

type Client struct {
	base      string
	psk       []byte
	serverPub *ecdh.PublicKey
	hc        *http.Client

	mu  sync.Mutex
	cur *csession
}

func (c *Client) current() *csession {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cur
}

func (c *Client) do(ctx context.Context, method, path string, body []byte, sid string) (*http.Response, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/octet-stream")
	} else {
		req.Header.Set("Cache-Control", "no-cache, no-store")
		req.Header.Set("Pragma", "no-cache")
	}
	if sid != "" {
		req.AddCookie(&http.Cookie{Name: "sid", Value: sid})
	}
	return c.hc.Do(req)
}

// connect performs the handshake and returns a live session.
// The handshake POST carries seq=0; the server ack also carries seq=0.
// Both are consumed here so that the window layer starts uniformly at seq=1.
func (c *Client) connect() (*csession, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	c2s, s2c, err := wire.ClientSession(eph, c.serverPub, c.psk)
	if err != nil {
		return nil, err
	}
	sidRaw := make([]byte, 16)
	rand.Read(sidRaw)
	sid := hex.EncodeToString(sidRaw)

	hello, err := c2s.Seal(wire.MarshalBatch(0, nil))
	if err != nil {
		return nil, err
	}
	body := make([]byte, 0, 1+32+len(hello))
	body = append(body, 1)
	body = append(body, eph.PublicKey().Bytes()...)
	body = append(body, hello...)

	ctx, cancel := context.WithTimeout(context.Background(), postTimeout)
	defer cancel()
	resp, err := c.do(ctx, http.MethodPost, "api/events", body, sid)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	ack, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, err
	}
	pt, err := s2c.Open(ack)
	if err != nil {
		return nil, errors.New("handshake rejected (check url/pub/psk)")
	}
	if _, _, err := wire.UnmarshalBatch(pt); err != nil {
		return nil, errors.New("handshake rejected: bad ack format")
	}

	return &csession{
		c2s: c2s, s2c: s2c, sid: sid,
		outQ:    make(chan wire.Frame, 1024),
		streams: make(map[uint32]*cstream),
		dead:    make(chan struct{}),
		downBuf: downReorderBuf{
			nextSeq: 1, // handshake consumed seq=0 on both directions
			pending: make(map[uint64][]wire.Frame),
			ready:   make(chan struct{}, 1),
		},
	}, nil
}

// sendBatch seals one upstream batch, sends it, and delivers the ack response
// (which is itself a seq-numbered downstream batch) to the reorder buffer.
func (c *Client) sendBatch(s *csession, seq uint64, batch []wire.Frame) error {
	sealed, err := s.c2s.Seal(wire.MarshalBatch(seq, batch))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), postTimeout)
	resp, err := c.do(ctx, http.MethodPost, "api/events", sealed, s.sid)
	if err != nil {
		cancel()
		return fmt.Errorf("post: %w", err)
	}
	blob, err := io.ReadAll(io.LimitReader(resp.Body, maxResp))
	resp.Body.Close()
	cancel()
	if err != nil {
		return fmt.Errorf("post read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("post status %d (body: %.120s)", resp.StatusCode, blob)
	}
	pt, err := s.s2c.Open(blob)
	if err != nil {
		return fmt.Errorf("post ack decrypt (status=%d len=%d): %w", resp.StatusCode, len(blob), err)
	}
	ackSeq, ackFrames, err := wire.UnmarshalBatch(pt)
	if err != nil {
		return err
	}
	s.downBuf.add(ackSeq, ackFrames)
	return nil
}

// sender coalesces outbound frames into batches and fires them in up to
// windowSize parallel POST lanes. Batches are seq-numbered in dispatch order
// so the server can reorder them before processing.
func (c *Client) sender(s *csession) {
	var upSeq atomic.Uint64
	upSeq.Store(1) // seq=0 consumed by the handshake POST

	sem := make(chan struct{}, windowSize)

	for {
		var batch []wire.Frame
		select {
		case f := <-s.outQ:
			batch = append(batch, f)
		case <-s.dead:
			return
		}
		var batchBytes int
		for _, f := range batch {
			batchBytes += len(f.Data)
		}
		timer := time.NewTimer(batchWindow)
	gather:
		for len(batch) < batchMax && batchBytes < maxBatchBody {
			select {
			case f := <-s.outQ:
				batch = append(batch, f)
				batchBytes += len(f.Data)
			case <-timer.C:
				break gather
			case <-s.dead:
				timer.Stop()
				return
			}
		}
		timer.Stop()

		select {
		case sem <- struct{}{}:
		case <-s.dead:
			return
		}

		seq := upSeq.Add(1) - 1

		go func(seq uint64, batch []wire.Frame) {
			defer func() { <-sem }()
			if err := c.sendBatch(s, seq, batch); err != nil {
				log.Printf("sender seq=%d: %v", seq, err)
				s.die()
			}
		}(seq, batch)
	}
}

// poller runs windowSize concurrent long-poll goroutines. Every response
// (including empty timeout flushes) carries a seq-numbered downstream batch
// that is fed into the session reorder buffer.
func (c *Client) poller(s *csession) {
	var wg sync.WaitGroup
	var pollSeq atomic.Uint64
	for i := 0; i < windowSize; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-s.dead:
					return
				default:
				}
				// Unique nonce prevents CDN from caching GET /api/updates responses.
				n := pollSeq.Add(1)
				path := "api/updates?n=" + strconv.FormatUint(n, 10)
				ctx, cancel := context.WithTimeout(context.Background(), pollTimeout)
				resp, err := c.do(ctx, http.MethodGet, path, nil, s.sid)
				if err != nil {
					cancel()
					log.Printf("poller: request: %v", err)
					s.die()
					return
				}
				blob, err := io.ReadAll(io.LimitReader(resp.Body, maxResp))
				resp.Body.Close()
				cancel()
				if err != nil {
					log.Printf("poller: read: %v", err)
					s.die()
					return
				}
				if resp.StatusCode != http.StatusOK {
					log.Printf("poller: status %d (body: %.120s)", resp.StatusCode, blob)
					s.die()
					return
				}
				pt, err := s.s2c.Open(blob)
				if err != nil {
					log.Printf("poller: decrypt (status=%d len=%d): %v", resp.StatusCode, len(blob), err)
					s.die()
					return
				}
				seq, frames, err := wire.UnmarshalBatch(pt)
				if err != nil {
					log.Printf("poller: unmarshal: %v", err)
					s.die()
					return
				}
				s.downBuf.add(seq, frames)
			}
		}()
	}
	wg.Wait()
}

// dispatcher drains the downstream reorder buffer and calls dispatch for each
// frame in seq order. It is the only goroutine that calls s.dispatch so there
// is no concurrent write to the same stream connection.
func (c *Client) dispatcher(s *csession) {
	for {
		select {
		case <-s.downBuf.ready:
			s.downBuf.drain(s.dispatch)
		case <-s.dead:
			// Drain whatever arrived before death.
			s.downBuf.drain(s.dispatch)
			return
		}
	}
}

const maxResp = 4 << 20 // 4 MiB downstream per poll

// ---------------------------------------------------------------------------
// DNS over HTTPS fallback (for operators that intercept UDP port 53)
// ---------------------------------------------------------------------------

type dohProvider struct{ ip, sni string }

// dohProviders lists DoH servers by fixed IP to avoid bootstrapping.
// Yandex is first — it is on Russian CDN whitelists.
var dohProviders = []dohProvider{
    {"77.88.8.8", "common.dot.dns.yandex.net"},
    {"8.8.8.8", "dns.google"},
}

type dohAnswer struct {
    Type int    `json:"type"`
    Data string `json:"data"`
}
type dohResp struct {
    Answer []dohAnswer `json:"Answer"`
}

func dohLookup(hostname string) (string, error) {
    for _, p := range dohProviders {
        hc := &http.Client{
            Timeout: 5 * time.Second,
            Transport: &http.Transport{
                TLSClientConfig: &tls.Config{ServerName: p.sni},
            },
        }
        req, _ := http.NewRequest("GET",
            "https://"+p.ip+"/dns-query?name="+hostname+"&type=A", nil)
        req.Header.Set("Accept", "application/dns-json")
        resp, err := hc.Do(req)
        if err != nil {
            log.Printf("doh %s: %v", p.sni, err)
            continue
        }
        var result dohResp
        decErr := json.NewDecoder(resp.Body).Decode(&result)
        resp.Body.Close()
        if decErr != nil {
            continue
        }
        for _, a := range result.Answer {
            if a.Type == 1 { // A record
                log.Printf("doh %s: %s → %s", p.sni, hostname, a.Data)
                return a.Data, nil
            }
        }
    }
    return "", errors.New("doh: all providers failed")
}

// supervise keeps a live session, reconnecting on failure.
func (c *Client) supervise() {
	backoff := time.Second
	for {
		s, err := c.connect()
		if err != nil {
			log.Printf("connect: %v (retry in %s)", err, backoff)
			time.Sleep(backoff)
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		log.Printf("session up (sid=%s…)", s.sid[:8])
		c.mu.Lock()
		c.cur = s
		c.mu.Unlock()

		go c.sender(s)
		go c.poller(s)
		go c.dispatcher(s)

		<-s.dead
		c.mu.Lock()
		if c.cur == s {
			c.cur = nil
		}
		c.mu.Unlock()
		s.teardown()
		log.Printf("session down, reconnecting")
	}
}

// ---------------------------------------------------------------------------
// SOCKS5 front end
// ---------------------------------------------------------------------------

func (c *Client) serveSOCKS(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go c.handleSOCKS(conn)
	}
}

func (c *Client) handleSOCKS(conn net.Conn) {
	target, err := socksHandshake(conn)
	if err != nil {
		conn.Close()
		return
	}
	s := c.current()
	if s == nil {
		conn.Close()
		return
	}
	id, _ := s.addStream(conn)

	send := func(f wire.Frame) bool {
		select {
		case s.outQ <- f:
			return true
		case <-s.dead:
			return false
		}
	}
	if !send(wire.Frame{Stream: id, Type: wire.FrameSYN, Data: []byte(target)}) {
		conn.Close()
		return
	}

	buf := make([]byte, wire.MaxData)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			d := make([]byte, n)
			copy(d, buf[:n])
			if !send(wire.Frame{Stream: id, Type: wire.FrameData, Data: d}) {
				return
			}
		}
		if err != nil {
			break
		}
	}
	send(wire.Frame{Stream: id, Type: wire.FrameFIN})
}

func socksReply(c net.Conn, code byte) {
	c.Write([]byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

func socksHandshake(c net.Conn) (string, error) {
	c.SetDeadline(time.Now().Add(30 * time.Second))
	b := make([]byte, 262)
	if _, err := io.ReadFull(c, b[:2]); err != nil {
		return "", err
	}
	if b[0] != 0x05 {
		return "", errors.New("not socks5")
	}
	nMethods := int(b[1])
	if _, err := io.ReadFull(c, b[:nMethods]); err != nil {
		return "", err
	}
	c.Write([]byte{0x05, 0x00}) // no auth

	if _, err := io.ReadFull(c, b[:4]); err != nil {
		return "", err
	}
	if b[1] != 0x01 { // only CONNECT
		socksReply(c, 0x07)
		return "", errors.New("unsupported command")
	}
	var host string
	switch b[3] {
	case 0x01:
		if _, err := io.ReadFull(c, b[:4]); err != nil {
			return "", err
		}
		host = net.IP(b[:4]).String()
	case 0x04:
		if _, err := io.ReadFull(c, b[:16]); err != nil {
			return "", err
		}
		host = net.IP(b[:16]).String()
	case 0x03:
		if _, err := io.ReadFull(c, b[:1]); err != nil {
			return "", err
		}
		l := int(b[0])
		if _, err := io.ReadFull(c, b[:l]); err != nil {
			return "", err
		}
		host = string(b[:l])
	default:
		socksReply(c, 0x08)
		return "", errors.New("bad address type")
	}
	if _, err := io.ReadFull(c, b[:2]); err != nil {
		return "", err
	}
	port := int(b[0])<<8 | int(b[1])
	socksReply(c, 0x00) // success
	c.SetDeadline(time.Time{})
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func main() {
	base := flag.String("url", "", "server base URL, e.g. https://notedeck.example/")
	pubHex := flag.String("pub", "", "server static public key (hex)")
	pskHex := flag.String("psk", "", "pre-shared key (hex)")
	socksAddr := flag.String("socks", "127.0.0.1:1080", "local SOCKS5 listen address")
	dnsAddr := flag.String("dns", "8.8.8.8:53", "DNS resolver for the server hostname (host or host:port)")
	flag.Parse()

	if *base == "" || *pubHex == "" || *pskHex == "" {
		log.Fatal("need -url, -pub and -psk")
	}
	if !strings.HasSuffix(*base, "/") {
		*base += "/"
	}
	rawPub, err := hex.DecodeString(*pubHex)
	if err != nil {
		log.Fatalf("bad -pub: %v", err)
	}
	pub, err := wire.PubFromBytes(rawPub)
	if err != nil {
		log.Fatalf("bad -pub: %v", err)
	}
	psk, err := hex.DecodeString(*pskHex)
	if err != nil {
		log.Fatalf("bad -psk: %v", err)
	}

	resolverAddr := *dnsAddr
	if resolverAddr != "" && !strings.Contains(resolverAddr, ":") {
		resolverAddr += ":53"
	}
	// UDP resolver: passed by the Android service (carrier's DNS from LinkProperties).
	// Avoids relying on the VPN TUN DNS which is not ready yet when we start.
	udpResolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			addr := resolverAddr
			if addr == "" {
				addr = "8.8.8.8:53"
			}
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "udp", addr)
		},
	}

	// udpBlocked is set to true after the first UDP DNS failure so subsequent
	// dials skip the 5-second UDP timeout and go straight to DoH.
	var udpBlocked atomic.Bool

	// dialCtx resolves hostnames with the carrier UDP DNS first.
	// If UDP port 53 is intercepted/blocked (e.g. MTS), it falls back to
	// DNS over HTTPS (Yandex → Google) which travels over port 443.
	dialCtx := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, splitErr := net.SplitHostPort(addr)
		dial := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		if splitErr != nil || net.ParseIP(host) != nil {
			// Already an IP or unparseable — connect directly without DNS.
			return dial.DialContext(ctx, network, addr)
		}

		var ip string
		if !udpBlocked.Load() {
			lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			addrs, err := udpResolver.LookupHost(lookupCtx, host)
			cancel()
			if err == nil && len(addrs) > 0 {
				ip = addrs[0]
			} else {
				log.Printf("UDP DNS failed (%v) — switching to DoH", err)
				udpBlocked.Store(true)
			}
		}
		if ip == "" {
			var dohErr error
			ip, dohErr = dohLookup(host)
			if dohErr != nil {
				return nil, fmt.Errorf("DNS failed (doh: %w)", dohErr)
			}
		}
		return dial.DialContext(ctx, network, net.JoinHostPort(ip, port))
	}

	cl := &Client{
		base:      *base,
		psk:       psk,
		serverPub: pub,
		hc: &http.Client{
			Transport: &http.Transport{
				ForceAttemptHTTP2:   true,
				MaxIdleConns:        32,
				MaxIdleConnsPerHost: 32,
				IdleConnTimeout:     90 * time.Second,
				DialContext:         dialCtx,
			},
			// no global timeout; per-request contexts bound each call
		},
	}

	go cl.supervise()

	ln, err := net.Listen("tcp", *socksAddr)
	if err != nil {
		log.Fatalf("listen socks: %v", err)
	}
	log.Printf("SOCKS5 on %s -> %s", *socksAddr, *base)
	cl.serveSOCKS(ln)
}
