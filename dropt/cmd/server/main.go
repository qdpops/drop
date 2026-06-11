// Command server is the DROP transport server. To anyone without the PSK it is
// an ordinary website ("Notedeck", a fake notes/sync SaaS). Real clients ride a
// covert channel hidden inside two plausible API endpoints:
//
//	POST /api/events    upstream  (client -> server), looks like telemetry
//	GET  /api/updates   downstream (server -> client), long-poll "sync"
//
// Requests whose bodies do not authenticate under the PSK get ordinary
// website/JSON responses, so an active prober cannot distinguish this host from
// a real site.
package main

import (
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"dropt/internal/wire"
)

const (
	maxBody      = 1 << 20  // 1 MiB per upstream POST
	maxDownBatch = 3 << 20  // 3 MiB max payload per downstream response
	pollHold     = 15 * time.Second
	dialTimeout  = 10 * time.Second
	streamInBuf  = 64
	sessionIdleT = 2 * time.Minute
)

// ---------------------------------------------------------------------------
// Upstream reorder buffer
//
// windowSize parallel POST lanes may deliver batches out of order. upstreamBuf
// holds out-of-order arrivals and calls processFrames in strict seq order.
// procMu ensures that at most one processFrames call runs at a time.
// ---------------------------------------------------------------------------

type upstreamBuf struct {
	mu      sync.Mutex
	procMu  sync.Mutex
	nextSeq uint64
	pending map[uint64][]wire.Frame
}

// deliver deposits seq into the buffer and, if this goroutine wins procMu,
// drains all consecutive in-order batches by calling fn on each.
func (b *upstreamBuf) deliver(seq uint64, fs []wire.Frame, fn func([]wire.Frame)) {
	b.mu.Lock()
	b.pending[seq] = fs
	_, hasNext := b.pending[b.nextSeq]
	b.mu.Unlock()
	if !hasNext {
		return
	}
	b.procMu.Lock()
	defer b.procMu.Unlock()
	b.mu.Lock()
	for {
		batch, ok := b.pending[b.nextSeq]
		if !ok {
			b.mu.Unlock()
			return
		}
		delete(b.pending, b.nextSeq)
		b.nextSeq++
		b.mu.Unlock()
		fn(batch)
		b.mu.Lock()
	}
}

// ---------------------------------------------------------------------------
// Per-stream and per-session state
// ---------------------------------------------------------------------------

type stream struct {
	conn      net.Conn
	in        chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

type session struct {
	c2s, s2c *wire.Cipher

	smu     sync.Mutex
	streams map[uint32]*stream

	omu     sync.Mutex
	outbuf  []wire.Frame
	downSeq uint64 // monotone counter for sealed downstream batches
	signal  chan struct{}

	upBuf upstreamBuf

	lastSeen time.Time
}

func (s *session) queue(f wire.Frame) {
	s.omu.Lock()
	s.outbuf = append(s.outbuf, f)
	s.omu.Unlock()
	select {
	case s.signal <- struct{}{}:
	default:
	}
}

// drainSeq atomically claims the next downstream seq number and drains up to
// maxDownBatch bytes from outbuf. If frames remain they are signalled for the
// next waiting poller so nothing is lost.
func (s *session) drainSeq() (uint64, []wire.Frame) {
	s.omu.Lock()
	var taken, total int
	for taken < len(s.outbuf) {
		total += len(s.outbuf[taken].Data)
		if taken > 0 && total > maxDownBatch {
			break
		}
		taken++
	}
	seq := s.downSeq
	s.downSeq++
	fs := make([]wire.Frame, taken)
	copy(fs, s.outbuf[:taken])
	s.outbuf = s.outbuf[taken:]
	hasMore := len(s.outbuf) > 0
	s.omu.Unlock()
	if hasMore {
		select {
		case s.signal <- struct{}{}:
		default:
		}
	}
	return seq, fs
}

func (s *session) getStream(id uint32) *stream {
	s.smu.Lock()
	defer s.smu.Unlock()
	return s.streams[id]
}

func (s *session) closeStream(id uint32) {
	s.smu.Lock()
	st := s.streams[id]
	delete(s.streams, id)
	s.smu.Unlock()
	if st != nil {
		st.closeOnce.Do(func() {
			close(st.closed)
			if st.conn != nil {
				st.conn.Close()
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

type Server struct {
	static *ecdh.PrivateKey
	psk    []byte
	site   http.Handler

	linkHost string // public hostname behind CDN, e.g. "example.cdn.ru"
	linkPath string // secret path serving the drop:// link, e.g. "/s/abc123"
	pubHex   string // hex-encoded static public key (cached for link generation)
	pskHex   string // hex-encoded PSK (cached for link generation)

	mu       sync.Mutex
	sessions map[string]*session
}

func (srv *Server) get(sid string) *session {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	s := srv.sessions[sid]
	if s != nil {
		s.lastSeen = time.Now()
	}
	return s
}

func (srv *Server) create(sid string, c2s, s2c *wire.Cipher) *session {
	s := &session{
		c2s: c2s, s2c: s2c,
		streams:  make(map[uint32]*stream),
		signal:   make(chan struct{}, 1),
		lastSeen: time.Now(),
		upBuf:    upstreamBuf{pending: make(map[uint64][]wire.Frame)},
	}
	srv.mu.Lock()
	srv.sessions[sid] = s
	srv.mu.Unlock()
	return s
}

func cookie(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

// handleEvents is the upstream endpoint. It either establishes a session
// (handshake) or carries client->server frames for an existing one.
func (srv *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		srv.site.ServeHTTP(w, r)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		fakeOK(w)
		return
	}
	sid := cookie(r, "sid")

	// Existing session: body is a sealed batch (seq | frames).
	if sid != "" {
		if s := srv.get(sid); s != nil {
			pt, err := s.c2s.Open(body)
			if err != nil {
				fakeOK(w) // wrong key / not really our client
				return
			}
			seq, frames, err := wire.UnmarshalBatch(pt)
			if err != nil {
				fakeOK(w)
				return
			}
			s.upBuf.deliver(seq, frames, func(fs []wire.Frame) {
				srv.processFrames(s, fs)
			})
			srv.ack(w, s)
			return
		}
	}

	// New session: body is [version(1)][ephPub(32)][sealed initial batch].
	if len(body) < 1+32 || body[0] != 1 || sid == "" {
		fakeOK(w)
		return
	}
	ephPub, err := wire.PubFromBytes(body[1:33])
	if err != nil {
		fakeOK(w)
		return
	}
	c2s, s2c, err := wire.ServerSession(srv.static, ephPub, srv.psk)
	if err != nil {
		fakeOK(w)
		return
	}
	pt, err := c2s.Open(body[33:])
	if err != nil {
		fakeOK(w) // PSK mismatch -> behave like a normal site
		return
	}
	_, frames, err := wire.UnmarshalBatch(pt)
	if err != nil {
		fakeOK(w)
		return
	}
	s := srv.create(sid, c2s, s2c)
	// Deliver the handshake batch (seq=0) to advance upBuf.nextSeq to 1.
	s.upBuf.deliver(0, frames, func(fs []wire.Frame) {
		srv.processFrames(s, fs)
	})
	srv.ack(w, s)
}

// handleUpdates is the downstream long-poll endpoint.
func (srv *Server) handleUpdates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		srv.site.ServeHTTP(w, r)
		return
	}
	s := srv.get(cookie(r, "sid"))
	if s == nil {
		// Unknown session: answer like a normal, idle sync endpoint.
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"updates":[]}`))
		return
	}
	deadline := time.NewTimer(pollHold)
	defer deadline.Stop()
	for {
		s.omu.Lock()
		hasData := len(s.outbuf) > 0
		s.omu.Unlock()
		if hasData {
			seq, fs := s.drainSeq()
			srv.writeSealed(w, s, seq, fs)
			return
		}
		select {
		case <-s.signal:
		case <-deadline.C:
			// Timeout: send an empty batch so the client repolls.
			seq, fs := s.drainSeq()
			srv.writeSealed(w, s, seq, fs)
			return
		case <-r.Context().Done():
			return
		}
	}
}

func (srv *Server) writeSealed(w http.ResponseWriter, s *session, seq uint64, fs []wire.Frame) {
	blob, err := s.s2c.Seal(wire.MarshalBatch(seq, fs))
	if err != nil {
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	noBuffer(w)
	w.Write(blob)
}

func (srv *Server) ack(w http.ResponseWriter, s *session) {
	seq, fs := s.drainSeq()
	srv.writeSealed(w, s, seq, fs)
}

func (srv *Server) processFrames(s *session, fs []wire.Frame) {
	for _, f := range fs {
		switch f.Type {
		case wire.FrameSYN:
			st := &stream{in: make(chan []byte, streamInBuf), closed: make(chan struct{})}
			s.smu.Lock()
			if old := s.streams[f.Stream]; old != nil {
				s.smu.Unlock()
				s.closeStream(f.Stream)
				s.smu.Lock()
			}
			s.streams[f.Stream] = st
			s.smu.Unlock()
			go srv.connect(s, f.Stream, string(f.Data), st)
		case wire.FrameData:
			if st := s.getStream(f.Stream); st != nil {
				select {
				case st.in <- f.Data:
				case <-st.closed:
				}
			}
		case wire.FrameFIN, wire.FrameRST:
			s.closeStream(f.Stream)
		}
	}
}

func (srv *Server) connect(s *session, id uint32, target string, st *stream) {
	conn, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		s.queue(wire.Frame{Stream: id, Type: wire.FrameRST})
		s.closeStream(id)
		return
	}
	st.conn = conn

	// target -> client
	go func() {
		buf := make([]byte, wire.MaxData)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				d := make([]byte, n)
				copy(d, buf[:n])
				s.queue(wire.Frame{Stream: id, Type: wire.FrameData, Data: d})
			}
			if err != nil {
				s.queue(wire.Frame{Stream: id, Type: wire.FrameFIN})
				s.closeStream(id)
				return
			}
		}
	}()

	// client -> target
	for {
		select {
		case data := <-st.in:
			if _, err := conn.Write(data); err != nil {
				s.closeStream(id)
				return
			}
		case <-st.closed:
			return
		}
	}
}

func (srv *Server) reaper() {
	for range time.Tick(30 * time.Second) {
		now := time.Now()
		srv.mu.Lock()
		for sid, s := range srv.sessions {
			if now.Sub(s.lastSeen) > sessionIdleT {
				delete(srv.sessions, sid)
				s.smu.Lock()
				for id := range s.streams {
					if st := s.streams[id]; st != nil && st.conn != nil {
						st.conn.Close()
					}
				}
				s.smu.Unlock()
			}
		}
		srv.mu.Unlock()
	}
}

// ---------------------------------------------------------------------------
// Camouflage helpers
// ---------------------------------------------------------------------------

func fakeOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}

func noBuffer(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Vary", "Cookie")
	w.Header().Set("X-Accel-Buffering", "no") // ask nginx/CDN not to buffer
}

// handleLink serves the drop:// connection link at the configured secret path.
// Only active when -link-host and -link-path are both set.
func (srv *Server) handleLink(w http.ResponseWriter, r *http.Request) {
	if srv.linkHost == "" || srv.linkPath == "" || r.URL.Path != srv.linkPath {
		srv.site.ServeHTTP(w, r)
		return
	}
	link := fmt.Sprintf("drop://%s/%s/%s", srv.linkHost, srv.pubHex, srv.pskHex)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprintf(w, linkHTML, link, link, link)
}

const linkHTML = `<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DROP — подключение</title>
<style>
:root{color-scheme:light dark}
body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f5f6fa;color:#1d2433;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#fff;border-radius:16px;padding:32px 28px;max-width:480px;width:90%%;box-shadow:0 4px 24px rgba(0,0,0,.08)}
h2{margin:0 0 8px;font-size:22px}
p{color:#5b6577;margin:0 0 24px;font-size:15px}
.link-box{background:#f0f4ff;border:1px solid #c7d4f8;border-radius:10px;padding:14px 16px;font-family:monospace;font-size:13px;word-break:break-all;color:#1a3a8f;margin-bottom:20px}
.btn{display:block;width:100%%;box-sizing:border-box;padding:13px;border-radius:10px;border:none;font-size:16px;font-weight:600;cursor:pointer;text-align:center;text-decoration:none;margin-bottom:10px}
.btn-primary{background:#2f6df6;color:#fff}
.btn-secondary{background:#f0f4ff;color:#2f6df6}
.copied{display:none;color:#16a34a;font-size:13px;margin-top:6px;text-align:center}
</style></head>
<body><div class="card">
<h2>DROP VPN</h2>
<p>Нажмите кнопку или скопируйте ссылку и вставьте в приложение.</p>
<div class="link-box">%s</div>
<a class="btn btn-primary" href="%s">Открыть в приложении</a>
<button class="btn btn-secondary" onclick="copyLink()">Скопировать ссылку</button>
<div class="copied" id="copied">✓ Скопировано</div>
</div>
<script>
function copyLink(){
  navigator.clipboard.writeText('%s').then(function(){
    var el=document.getElementById('copied');
    el.style.display='block';
    setTimeout(function(){el.style.display='none'},2000);
  });
}
</script>
</body></html>`

func main() {
	listen := flag.String("listen", ":8080", "listen address (put TLS/CDN in front)")
	staticHex := flag.String("static", "", "server static private key (hex, from keygen)")
	pskHex := flag.String("psk", "", "pre-shared key (hex, from keygen)")
	siteDir := flag.String("site", "", "optional directory of real static files to serve as the site")
	linkHost := flag.String("link-host", "", "public hostname for drop:// links, e.g. example.cdn.ru")
	linkPath := flag.String("link-path", "", "secret path to serve the connection link, e.g. /s/abc123")
	flag.Parse()

	if *staticHex == "" || *pskHex == "" {
		log.Fatal("need -static and -psk (run the keygen tool)")
	}
	rawStatic, err := hex.DecodeString(*staticHex)
	if err != nil {
		log.Fatalf("bad -static: %v", err)
	}
	priv, err := wire.PrivFromBytes(rawStatic)
	if err != nil {
		log.Fatalf("bad -static: %v", err)
	}
	psk, err := hex.DecodeString(*pskHex)
	if err != nil {
		log.Fatalf("bad -psk: %v", err)
	}

	var site http.Handler
	if *siteDir != "" {
		site = http.FileServer(http.Dir(*siteDir))
	} else {
		site = http.HandlerFunc(serveDecoy)
	}

	srv := &Server{
		static:   priv,
		psk:      psk,
		site:     site,
		sessions: make(map[string]*session),
		linkHost: *linkHost,
		linkPath: strings.TrimRight(*linkPath, "/"),
		pubHex:   hex.EncodeToString(priv.PublicKey().Bytes()),
		pskHex:   *pskHex,
	}
	go srv.reaper()

	if srv.linkPath != "" && srv.linkHost != "" {
		log.Printf("Connection link: https://%s%s", srv.linkHost, srv.linkPath)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/events", srv.handleEvents)
	mux.HandleFunc("/api/updates", srv.handleUpdates)
	mux.HandleFunc("/", srv.handleLink) // serves link page or falls through to site

	hs := &http.Server{
		Addr:    *listen,
		Handler: mux,
		// ReadTimeout covers reading the request body (upstream POST batches ≤ 1 MiB).
		ReadTimeout: 35 * time.Second,
		// WriteTimeout must exceed pollHold (15s) + nginx proxy_read_timeout (65s) margin.
		// Set to 0 (no limit) — each handler manages its own context deadline instead.
		WriteTimeout: 0,
		IdleTimeout:  120 * time.Second,
	}
	log.Printf("DROP server on %s (site=%s)", *listen, siteSource(*siteDir))

	// Graceful shutdown: release the port cleanly so the next instance can bind
	// immediately when systemd restarts the service (avoids "address already in use").
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-quit
		log.Printf("shutting down (signal received)")
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		hs.Shutdown(ctx) //nolint:errcheck
	}()

	if err := hs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("ListenAndServe: %v", err)
	}
}

func siteSource(dir string) string {
	if dir == "" {
		return "embedded decoy"
	}
	if _, err := os.Stat(dir); err != nil {
		return dir + " (missing!)"
	}
	return dir
}

func serveDecoy(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		w.WriteHeader(http.StatusNotFound)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(notFoundHTML))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(indexHTML))
}

const indexHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Notedeck — notes that sync</title>
<style>
:root{color-scheme:light dark}
body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;color:#1d2433;background:#fbfcfe}
.wrap{max-width:760px;margin:0 auto;padding:64px 24px}
h1{font-size:40px;letter-spacing:-.02em;margin:0 0 8px}
p.lead{font-size:19px;color:#5b6577;margin:0 0 32px}
.cta{display:inline-block;background:#2f6df6;color:#fff;text-decoration:none;padding:12px 22px;border-radius:10px;font-weight:600}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:48px}
.card{border:1px solid #e6e9f0;border-radius:14px;padding:20px;background:#fff}
.card h3{margin:0 0 6px;font-size:16px}
.card p{margin:0;color:#5b6577;font-size:14px}
footer{color:#8a93a6;font-size:13px;margin-top:56px}
@media(max-width:560px){.grid{grid-template-columns:1fr}}
</style></head>
<body><div class="wrap">
<h1>Notedeck</h1>
<p class="lead">Fast, private notes that stay in sync across every device. No setup, no clutter.</p>
<a class="cta" href="/signup">Get started</a>
<div class="grid">
<div class="card"><h3>Realtime sync</h3><p>Changes propagate instantly to every connected client.</p></div>
<div class="card"><h3>Offline first</h3><p>Keep writing without a connection; we reconcile when you're back.</p></div>
<div class="card"><h3>End-to-end</h3><p>Your notes are encrypted on device before they ever leave it.</p></div>
<div class="card"><h3>Open API</h3><p>Build on top of Notedeck with a simple events and updates API.</p></div>
</div>
<footer>© Notedeck. All rights reserved.</footer>
</div></body></html>`

const notFoundHTML = `<!doctype html><html><head><meta charset="utf-8"><title>Not found</title>
<style>body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:560px;margin:80px auto;padding:0 24px;color:#1d2433}</style>
</head><body><h1>404</h1><p>That page doesn't exist. <a href="/">Back home</a>.</p></body></html>`
