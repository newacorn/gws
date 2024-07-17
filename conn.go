package gws

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"github.com/lxzan/gws/internal"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type Conn struct {
	mu sync.Mutex // 写锁
	// 缺省值为此函数返回值：func newSmap() *smap { return &smap{data: make(map[string]any)} }
	ss       SessionStorage // 会话
	err      atomic.Value   // 错误
	isServer bool           // 是否为服务器
	// 握手时设置
	subprotocol string   // 子协议
	conn        net.Conn // 底层连接
	config      *Config  // 配置
	// 默认4096
	br                *bufio.Reader     // 读缓存
	continuationFrame continuationFrame // 连续帧
	fh                frameHeader       // 帧头
	handler           Event             // 事件处理器
	closed            uint32            // 是否关闭, 原子性关闭会话
	readQueue         channel           // 消息处理队列，OnMessage方法并发数控制器，默认为并发为8
	writeQueue        workerQueue       // 发送队列，异步Write发送的消息帧和广播消息会进入此队列， 每个连接最多同时只有一个worker再处理这个队列中的任务
	deflater          *deflater         // 压缩编码器
	dpsWindow         slideWindow       // 解压器滑动窗口
	cpsWindow         slideWindow       // 压缩器滑动窗口
	pd                PermessageDeflate // 压缩拓展协商结果
	pingControl       *pingControl
}
type pingControl struct {
	stop   chan struct{}
	ponged atomic.Bool
	ticker *time.Ticker
}

func (p *pingControl) SetPonged() {
	p.ponged.Store(true)
}

func (p *pingControl) start(s *Conn) {
out:
	for {
		select {
		case <-p.stop:
			p.ticker.Stop()
			break out
		case <-p.ticker.C:
			if !p.ponged.Load() {
				p.ticker.Stop()
				s.WriteClose(1000, nil)
				break out
			}
			_ = s.WritePing(nil)
			p.ponged.Store(false)
		}
	}
}

// ReadLoop 循环读取消息. 如果复用了HTTP Server, 建议开启goroutine, 阻塞会导致请求上下文无法被GC.
// Read messages in a loop.
// If HTTP Server is reused, it is recommended to enable goroutine, as blocking will prevent the context from being GC.
func (c *Conn) ReadLoop() {
	c.handler.OnOpen(c)
	for {
		if err := c.readMessage(); err != nil {
			c.emitError(err)
			break
		}
	}
	// 当执行write操作发生错误时，会向对端发送关闭帧并关闭底层net.Conn。
	// 还会将引起关闭的err存存储到Conn的err字段中。
	//
	// 上面的Read循环会因为从关闭的tcp链接中读取消息而返回。
	// 因为Conn的closed字段原子保护，err字段要么是Read操作存储的，要么是Write操作存储的
	// 不会产生覆盖。无论谁存储的err都会被用来调用OnClose方法。
	//
	// 所以Write不会主动调用OnClose方法也不会主动回收资源，靠的时Read操作观察到Write操作关闭
	// 底层连接产生的错误触发的。
	//
	// 未发现err是中存储的不是error类型的情景
	err, ok := c.err.Load().(error)
	c.handler.OnClose(c, internal.SelectValue(ok, err, errEmpty))

	// 回收资源
	if c.isServer {
		c.br.Reset(nil)
		c.config.brPool.Put(c.br)
		c.br = nil

		if c.cpsWindow.enabled {
			c.config.cswPool.Put(c.cpsWindow.dict)
			c.cpsWindow.dict = nil
		}
		if c.dpsWindow.enabled {
			c.config.dswPool.Put(c.dpsWindow.dict)
			c.dpsWindow.dict = nil
		}
	}
}

func (c *Conn) getCpsDict(isBroadcast bool) []byte {
	// 广播模式必须保证每一帧都是相同的内容, 所以不使用上下文接管优化压缩率
	if isBroadcast {
		return nil
	}
	if c.isServer && c.pd.ServerContextTakeover {
		return c.cpsWindow.dict
	}
	if !c.isServer && c.pd.ClientContextTakeover {
		return c.cpsWindow.dict
	}
	return nil
}
func (c *Conn) SetPonged() {
	c.pingControl.SetPonged()
}

func (c *Conn) getDpsDict() []byte {
	if c.isServer && c.pd.ClientContextTakeover {
		return c.dpsWindow.dict
	}
	if !c.isServer && c.pd.ServerContextTakeover {
		return c.dpsWindow.dict
	}
	return nil
}

func (c *Conn) isTextValid(opcode Opcode, payload []byte) bool {
	if c.config.CheckUtf8Enabled {
		return internal.CheckEncoding(uint8(opcode), payload)
	}
	return true
}

func (c *Conn) isClosed() bool { return atomic.LoadUint32(&c.closed) == 1 }

//goland:noinspection GoTypeAssertionOnErrors
func (c *Conn) close(reason []byte, err error) {
	c.err.Store(err)
	switch err.(type) {
	case EmitCloseError:
		_ = c.doWrite(OpcodeCloseConnection, internal.Bytes(reason))
	case *CloseError:
		_ = c.doWrite(OpcodeCloseConnection, internal.Bytes(reason))
	}
	//_ = c.doWrite(OpcodeCloseConnection, internal.Bytes(reason))
	_ = c.conn.Close()
}

// 仅由Write类方法和ReadLoop中的readMessage方法所调用
func (c *Conn) emitError(err error) {
	if err == nil {
		return
	}

	if atomic.CompareAndSwapUint32(&c.closed, 0, 1) {
		var responseCode = internal.CloseNormalClosure
		var responseErr error = internal.CloseNormalClosure
		switch v := err.(type) {
		case internal.StatusCode:
			responseCode = v
		case *internal.Error:
			responseCode = v.Code
			responseErr = v.Err
		default:
			responseErr = err
		}

		var content = responseCode.Bytes()
		content = append(content, err.Error()...)
		if len(content) > internal.ThresholdV1 {
			content = content[:internal.ThresholdV1]
		}

		c.close(content, responseErr)
	}
}

// 仅由readControl方法所调用
func (c *Conn) emitClose(buf *bytes.Buffer) error {
	var responseCode = internal.CloseNormalClosure
	var realCode = internal.CloseNormalClosure.Uint16()
	switch buf.Len() {
	case 0:
		responseCode = 0
		realCode = 0
	case 1:
		responseCode = internal.CloseProtocolError
		realCode = uint16(buf.Bytes()[0])
		buf.Reset()
	default:
		var b [2]byte
		_, _ = buf.Read(b[0:])
		realCode = binary.BigEndian.Uint16(b[0:])
		switch realCode {
		case 1004, 1005, 1006, 1014, 1015:
			responseCode = internal.CloseProtocolError
		default:
			if realCode < 1000 || realCode >= 5000 || (realCode >= 1016 && realCode < 3000) {
				responseCode = internal.CloseProtocolError
			} else if realCode < 1016 {
				responseCode = internal.CloseNormalClosure
			} else {
				responseCode = internal.StatusCode(realCode)
			}
		}
		if !c.isTextValid(OpcodeCloseConnection, buf.Bytes()) {
			responseCode = internal.CloseUnsupportedData
		}
	}
	if atomic.CompareAndSwapUint32(&c.closed, 0, 1) {
		c.close(responseCode.Bytes(), &CloseError{Code: realCode, Reason: buf.Bytes()})
	}
	return internal.CloseNormalClosure
}

// SetDeadline sets deadline
func (c *Conn) SetDeadline(t time.Time) error {
	err := c.conn.SetDeadline(t)
	c.emitError(err)
	return err
}

// SetReadDeadline sets read deadline
func (c *Conn) SetReadDeadline(t time.Time) error {
	err := c.conn.SetReadDeadline(t)
	c.emitError(err)
	return err
}

// SetWriteDeadline sets write deadline
func (c *Conn) SetWriteDeadline(t time.Time) error {
	err := c.conn.SetWriteDeadline(t)
	c.emitError(err)
	return err
}

func (c *Conn) LocalAddr() net.Addr { return c.conn.LocalAddr() }

func (c *Conn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

// NetConn get tcp/tls/kcp... connection
func (c *Conn) NetConn() net.Conn { return c.conn }

// SetNoDelay controls whether the operating system should delay
// packet transmission in hopes of sending fewer packets (Nagle's
// algorithm).  The default is true (no delay), meaning that data is
// sent as soon as possible after a Write.
func (c *Conn) SetNoDelay(noDelay bool) error {
	switch v := c.conn.(type) {
	case *net.TCPConn:
		return v.SetNoDelay(noDelay)
	case *tls.Conn:
		if netConn, ok := v.NetConn().(*net.TCPConn); ok {
			return netConn.SetNoDelay(noDelay)
		}
	}
	return nil
}

// SubProtocol 获取协商的子协议
// Get negotiated sub-protocols
func (c *Conn) SubProtocol() string { return c.subprotocol }

// Session 获取会话存储
// get session storage
func (c *Conn) Session() SessionStorage { return c.ss }
