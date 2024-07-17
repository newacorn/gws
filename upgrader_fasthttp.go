package gws

import (
	"bufio"
	"errors"
	"github.com/lxzan/gws/internal"
	"github.com/newacorn/fasthttp"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"utils/unsafefn"
)

var windowBitsTable = [8]string{"8", "9", "10", "11", "12", "13", "14", "15"}

func (c *Upgrader) UpgradeFastHttp(ctx *fasthttp.RequestCtx) (*Conn, error) {
	netConn, br, err := c.hijackFastHttp(ctx)
	if err != nil {
		return nil, err
	}
	return c.UpgradeFromConnFastHttp(netConn, br, ctx)
}

// UpgradeFromConnFastHttp 从连接(TCP/KCP/Unix Domain Socket...)升级到WebSocket协议
// From connection (TCP/KCP/Unix Domain Socket...) Upgrade to WebSocket protocol
func (c *Upgrader) UpgradeFromConnFastHttp(conn net.Conn, br *bufio.Reader, ctx *fasthttp.RequestCtx) (*Conn, error) {
	socket, err := c.doUpgradeFromConnFastHttp(conn, br, ctx)
	if err != nil {
		_ = c.writeErr(conn, err)
		_ = conn.Close()
	}
	return socket, err
}

func (c *responseWriter) WithSubProtocolFastHttp(ctx *fasthttp.RequestCtx, expectedSubProtocols []string) {
	if len(expectedSubProtocols) > 0 {
		c.subprotocol = internal.GetIntersectionElem(expectedSubProtocols, internal.Split(string(ctx.Request.Header.Peek(internal.SecWebSocketProtocol.Key)), ","))
		if c.subprotocol == "" {
			c.err = ErrSubprotocolNegotiation
			return
		}
		c.WithHeader(internal.SecWebSocketProtocol.Key, c.subprotocol)
	}
}
func (c *Upgrader) doUpgradeFromConnFastHttp(netConn net.Conn, br *bufio.Reader, ctx *fasthttp.RequestCtx) (*Conn, error) {
	var session = c.option.NewSession()
	if !c.option.AuthorizeFastHttp(ctx, session) {
		return nil, ErrUnauthorized
	}

	if unsafefn.B2S(ctx.Method()) != http.MethodGet {
		return nil, ErrHandshake
	}
	if !strings.EqualFold(requestCtxStrHeader(ctx, internal.SecWebSocketVersion.Key), internal.SecWebSocketVersion.Val) {
		return nil, errors.New("gws: websocket version not supported")
	}
	if !internal.HttpHeaderContains(requestCtxStrHeader(ctx, internal.Connection.Key), internal.Connection.Val) {
		return nil, ErrHandshake
	}
	if !strings.EqualFold(requestCtxStrHeader(ctx, internal.Upgrade.Key), internal.Upgrade.Val) {
		return nil, ErrHandshake
	}

	var rw = new(responseWriter).Init()
	defer rw.Close()

	var extensions = requestCtxStrHeader(ctx, internal.SecWebSocketExtensions.Key)
	var pd = c.getPermessageDeflate(extensions)
	if pd.Enabled {
		pd.writeResponseHeader(rw)
	}

	var websocketKey = requestCtxStrHeader(ctx, internal.SecWebSocketKey.Key)
	if websocketKey == "" {
		return nil, ErrHandshake
	}
	rw.WithHeader(internal.SecWebSocketAccept.Key, internal.ComputeAcceptKey(websocketKey))
	rw.WithSubProtocolFastHttp(ctx, c.option.SubProtocols)
	rw.WithExtraHeader(c.option.ResponseHeader)
	if err := rw.Write(netConn, c.option.HandshakeTimeout); err != nil {
		return nil, err
	}

	config := c.option.getConfig()
	socket := &Conn{
		ss:                session,
		isServer:          true,
		subprotocol:       rw.subprotocol,
		pd:                pd,
		conn:              netConn,
		config:            config,
		br:                br,
		continuationFrame: continuationFrame{},
		fh:                frameHeader{},
		handler:           c.eventHandler,
		closed:            0,
		writeQueue:        workerQueue{maxConcurrency: 1},
		readQueue:         make(channel, c.option.ParallelGolimit),
	}
	if c.option.PingInterval > 0 {
		socket.pingControl = &pingControl{
			ticker: time.NewTicker(c.option.PingInterval),
			stop:   make(chan struct{}),
		}
		socket.pingControl.ponged.Store(true)
		go socket.pingControl.start(socket)
	}
	//
	if pd.Enabled {
		socket.deflater = c.deflaterPool.Select()
		if c.option.PermessageDeflate.ServerContextTakeover {
			socket.cpsWindow.initialize(config.cswPool, c.option.PermessageDeflate.ServerMaxWindowBits)
		}
		if c.option.PermessageDeflate.ClientContextTakeover {
			socket.dpsWindow.initialize(config.dswPool, c.option.PermessageDeflate.ClientMaxWindowBits)
		}
	}
	return socket, nil
}
func requestCtxStrHeader(ctx *fasthttp.RequestCtx, key string) (v string) {
	v = unsafefn.B2S(ctx.Request.Header.Peek(key))
	return
}
func (c *PermessageDeflate) writeRequestHeader(rw *responseWriter) {
	rw.b.WriteString(internal.SecWebSocketExtensions.Key)
	rw.b.WriteString(": ")
	rw.b.WriteString(internal.PermessageDeflate)
	rw.b.WriteString("; ")
	if !c.ServerContextTakeover {
		rw.b.WriteString(internal.ServerNoContextTakeover)
		rw.b.WriteString("; ")
	}
	if !c.ClientContextTakeover {
		rw.b.WriteString(internal.ClientNoContextTakeover)
		rw.b.WriteString("; ")
	}
	if c.ServerMaxWindowBits != 15 {

		rw.b.WriteString(internal.ServerMaxWindowBits + internal.EQ + strconv.Itoa(c.ServerMaxWindowBits))
		rw.b.WriteString("; ")
	}
	if c.ClientMaxWindowBits != 15 {
		rw.b.WriteString(internal.ClientMaxWindowBits + internal.EQ + strconv.Itoa(c.ClientMaxWindowBits))
	} else if c.ClientContextTakeover {
		rw.b.WriteString(internal.ClientMaxWindowBits)
	}
	rw.b.WriteString("\r\n")
}

func (c *PermessageDeflate) writeResponseHeader(rw *responseWriter) {
	rw.b.WriteString(internal.SecWebSocketExtensions.Key)
	rw.b.WriteString(": ")
	rw.b.WriteString(internal.PermessageDeflate)
	if !c.ServerContextTakeover {
		rw.b.WriteString("; ")
		rw.b.WriteString(internal.ServerNoContextTakeover)
	}
	if !c.ClientContextTakeover {
		rw.b.WriteString("; ")
		rw.b.WriteString(internal.ClientNoContextTakeover)
	}
	if c.ServerMaxWindowBits != 15 {
		rw.b.WriteString("; ")
		rw.b.WriteString(internal.ServerMaxWindowBits)
		rw.b.WriteString(internal.EQ)
		rw.b.WriteString(windowBitsTable[c.ServerMaxWindowBits-8])
	}
	if c.ClientMaxWindowBits != 15 {
		rw.b.WriteString("; ")
		rw.b.WriteString(internal.ClientMaxWindowBits)
		rw.b.WriteString(internal.EQ)
		rw.b.WriteString(windowBitsTable[c.ClientMaxWindowBits-8])
	}
	rw.b.WriteString("\r\n")
}

// 为了节省内存, 不复用hijack返回的bufio.ReadWriter
func (c *Upgrader) hijackFastHttp(ctx *fasthttp.RequestCtx) (net.Conn, *bufio.Reader, error) {
	ctx.HijackSetNoResponse(true)
	// 空的Hijack处理闭包，让ctx上的关联资源立即回收
	// fastHttp.Server 需设置为保留不回收hijack的net.Conn
	ctx.Hijack(func(c net.Conn) {
	})
	netConn := ctx.Conn()
	br := c.option.config.brPool.Get()
	br.Reset(netConn)
	return netConn, br, nil
}
