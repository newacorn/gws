package gws

import (
	"bufio"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/klauspost/compress/flate"
	"github.com/lxzan/gws/internal"
)

const (
	defaultParallelGolimit     = 8
	defaultCompressLevel       = flate.BestSpeed
	defaultReadMaxPayloadSize  = 16 * 1024 * 1024
	defaultWriteMaxPayloadSize = 16 * 1024 * 1024
	defaultCompressThreshold   = 512
	defaultCompressorPoolSize  = 32
	defaultReadBufferSize      = 4 * 1024
	defaultWriteBufferSize     = 4 * 1024
	defaultHandshakeTimeout    = 5 * time.Second
	defaultDialTimeout         = 5 * time.Second
)

type (
	// PermessageDeflate 压缩拓展配置
	// 对于gws client, 建议开启上下文接管, 不修改滑动窗口指数, 提供最好的兼容性.
	// 对于gws server, 如果开启上下文接管, 每个连接会占用更多内存, 合理配置滑动窗口指数.
	// For gws client, it is recommended to enable contextual takeover and not modify the sliding window index to provide the best compatibility.
	// For gws server, if you turn on context-side takeover, each connection takes up more memory, configure the sliding window index appropriately.
	PermessageDeflate struct {
		// 是否开启压缩
		// Whether to turn on compression
		// serverPD.Enabled && strings.Contains(extensions, internal.PermessageDeflate)
		// 客户端握手消息和服务端配置共同决定
		Enabled bool

		// 压缩级别
		// Compress level
		// defaultCompressLevel = 1
		// 配置决定
		Level int

		// 压缩阈值, 长度小于阈值的消息不会被压缩, 仅适用于无上下文接管模式.
		// Compression threshold, messages below the threshold will not be compressed, only for context-free takeover mode.
		// defaultCompressThreshold 512
		// 配置决定
		Threshold int

		// 压缩器内存池大小
		// 数值越大竞争的概率越小, 但是会耗费大量内存
		// Compressor memory pool size
		// The higher the value the lower the probability of competition, but it will consume a lot of memory
		//
		// 缺省值为32
		// 配置决定
		PoolSize int

		// 服务端上下文接管
		// Server side context takeover
		// 缺省值为false
		//
		// clientPD.ServerContextTakeover && serverPD.ServerContextTakeover
		// 服务端：客户端握手消息和服务端配置共同决定
		// 客户端：客户端配置后，根据服务端的响应决定是否开启，即相信服务端会根据客户端的请求头
		// 做出正确的响应头
		ServerContextTakeover bool

		// 客户端上下文接管
		// Client side context takeover
		// 缺省值为false
		//
		// clientPD.ClientContextTakeover && serverPD.ClientContextTakeover,
		// 服务端：客户端握手消息和服务端配置共同决定
		// 客户端：客户端配置后，根据服务端的响应决定是否开启，即相信服务端会根据客户端的请求头
		// 做出正确的响应头
		ClientContextTakeover bool

		// 服务端滑动窗口指数
		// 取值范围 8<=n<=15, 表示pow(2,n)个字节
		// The server-side sliding window index
		// Range 8<=n<=15, means pow(2,n) bytes.
		//
		// ServerContextTakeover = true时, 默认12
		// false时, 默认15
		// 服务端：配置决定
		// 客户端：尊重服务端响应头
		ServerMaxWindowBits int

		// 客户端滑动窗口指数
		// 取值范围 8<=x<=15, 表示pow(2,n)个字节
		// The client-side sliding window index
		// Range 8<=n<=15, means pow(2,n) bytes.
		//
		// ClientContextTakeover = true时, 默认12
		// false时，默认为15
		// 服务端：配置决定
		// 客户端：尊重服务端响应头
		ClientMaxWindowBits int
	}

	Config struct {
		// bufio.Reader内存池
		brPool *internal.Pool[*bufio.Reader]

		// 压缩器滑动窗口内存池
		cswPool *internal.Pool[[]byte]

		// 解压器滑动窗口内存池
		dswPool *internal.Pool[[]byte]

		// 是否开启并行消息处理
		// Whether to enable parallel message processing
		// 开启OnMessage方法并发执行
		// 缺省值为false
		ParallelEnabled bool

		// (单个连接)用于并行消息处理的协程数量限制
		// Limit on the number of concurrent goroutine used for parallel message processing (single connection)
		// 缺省值为8
		// OnMessage方法并发执行的数量
		ParallelGolimit int

		// 最大读取的消息内容长度
		// 超过此值直接返回 internal.CloseMessageTooLarge 错误
		// Maximum read message content length
		// 默认16MB
		ReadMaxPayloadSize int

		// 读缓冲区的大小
		// Size of the read buffer
		// defaultReadBufferSize
		// 4096字节
		ReadBufferSize int

		// 最大写入的消息内容长度
		// Maximum length of written message content
		// 默认16MB
		WriteMaxPayloadSize int

		// 写缓冲区的大小, v1.4.5版本此参数被废弃
		// Deprecated: Size of the write buffer, v1.4.5 version of this parameter is deprecated
		WriteBufferSize int

		// 是否检查文本utf8编码, 关闭性能会好点
		// Whether to check the text utf8 encoding, turn off the performance will be better
		// 默认为false
		CheckUtf8Enabled bool

		// 消息回调(OnMessage)的恢复程序
		// Message callback (OnMessage) recovery program
		// OnMessage方法返回后会调用此函数
		//
		// 缺省时为无操作函数func(logger Logger) {}
		Recovery func(logger Logger)

		// 日志工具
		// Logging tools
		// 缺省值为 stdLogger
		Logger Logger
	}

	ServerOption struct {
		config *Config

		// 写缓冲区的大小, v1.4.5版本此参数被废弃
		// Deprecated: Size of the write buffer, v1.4.5 version of this parameter is deprecated
		WriteBufferSize int

		PermessageDeflate   PermessageDeflate
		ParallelEnabled     bool
		ParallelGolimit     int
		ReadMaxPayloadSize  int
		ReadBufferSize      int
		WriteMaxPayloadSize int
		CheckUtf8Enabled    bool
		Logger              Logger
		Recovery            func(logger Logger)

		// TLS设置
		TlsConfig *tls.Config

		// 握手超时时间
		// 默认为5s
		HandshakeTimeout time.Duration

		// WebSocket子协议, 握手失败会断开连接
		// WebSocket sub-protocol, handshake failure disconnects the connection
		SubProtocols []string

		// 额外的响应头(可能不受客户端支持)
		// Additional response headers (may not be supported by the client)
		// https://www.rfc-editor.org/rfc/rfc6455.html#section-1.3
		ResponseHeader http.Header

		// 鉴权
		// Authentication of requests for connection establishment
		Authorize         func(r *http.Request, session SessionStorage) bool

		// 创建session存储空间
		// 用于自定义SessionStorage实现
		// For custom SessionStorage implementations
		NewSession   func() SessionStorage
		PingInterval time.Duration
	}
)

var (
	defaultBrPool      *internal.Pool[*bufio.Reader]
	defaultBrPoolOnce  sync.Once
	defaultDswCswPools = [15 - 8 + 1]*internal.Pool[[]byte]{}
)

func init() {
	for i := 8; i <= 15; i++ {
		defaultDswCswPools[i-8] = getDswCswPool(i)
	}
}

// 设置压缩阈值
// 开启上下文接管时, 必须不论长短压缩全部消息, 否则浏览器会报错
// when context takeover is enabled, all messages must be compressed regardless of length,
// otherwise the browser will report an error.
func (c *PermessageDeflate) setThreshold(isServer bool) {
	if (isServer && c.ServerContextTakeover) || (!isServer && c.ClientContextTakeover) {
		c.Threshold = 0
	}
}

func (c *ServerOption) deleteProtectedHeaders() {
	c.ResponseHeader.Del(internal.Upgrade.Key)
	c.ResponseHeader.Del(internal.Connection.Key)
	c.ResponseHeader.Del(internal.SecWebSocketAccept.Key)
	c.ResponseHeader.Del(internal.SecWebSocketExtensions.Key)
	c.ResponseHeader.Del(internal.SecWebSocketProtocol.Key)
}

func getDswCswPool(n int) *internal.Pool[[]byte] {
	windowSize := internal.BinaryPow(n)
	return internal.NewPool(func() []byte {
		return make([]byte, 0, windowSize)
	})
}

func initServerOption(c *ServerOption) *ServerOption {

	if c == nil {
		c = new(ServerOption)
	}
	if c.ReadMaxPayloadSize <= 0 {
		c.ReadMaxPayloadSize = defaultReadMaxPayloadSize
	}
	if c.ParallelGolimit <= 0 {
		c.ParallelGolimit = defaultParallelGolimit
	}
	if c.ReadBufferSize <= 0 {
		c.ReadBufferSize = defaultReadBufferSize
	}
	if c.WriteMaxPayloadSize <= 0 {
		c.WriteMaxPayloadSize = defaultWriteMaxPayloadSize
	}
	if c.WriteBufferSize <= 0 {
		c.WriteBufferSize = defaultWriteBufferSize
	}
	if c.Authorize == nil {
		c.Authorize = func(r *http.Request, session SessionStorage) bool { return true }
	}
	if c.NewSession == nil {
		c.NewSession = func() SessionStorage { return newSmap() }
	}
	if c.ResponseHeader == nil {
		c.ResponseHeader = http.Header{}
	}
	if c.HandshakeTimeout <= 0 {
		c.HandshakeTimeout = defaultHandshakeTimeout
	}
	if c.Logger == nil {
		c.Logger = defaultLogger
	}
	if c.Recovery == nil {
		c.Recovery = func(logger Logger) {}
	}

	if c.PermessageDeflate.Enabled {
		if c.PermessageDeflate.ServerMaxWindowBits < 8 || c.PermessageDeflate.ServerMaxWindowBits > 15 {
			c.PermessageDeflate.ServerMaxWindowBits = internal.SelectValue(c.PermessageDeflate.ServerContextTakeover, 12, 15)
		}
		if c.PermessageDeflate.ClientMaxWindowBits < 8 || c.PermessageDeflate.ClientMaxWindowBits > 15 {
			c.PermessageDeflate.ClientMaxWindowBits = internal.SelectValue(c.PermessageDeflate.ClientContextTakeover, 12, 15)
		}
		if c.PermessageDeflate.Threshold <= 0 {
			c.PermessageDeflate.Threshold = defaultCompressThreshold
		}
		if c.PermessageDeflate.Level == 0 {
			c.PermessageDeflate.Level = defaultCompressLevel
		}
		if c.PermessageDeflate.PoolSize <= 0 {
			c.PermessageDeflate.PoolSize = defaultCompressorPoolSize
		}
		c.PermessageDeflate.PoolSize = internal.ToBinaryNumber(c.PermessageDeflate.PoolSize)
	}

	c.deleteProtectedHeaders()

	defaultBrPoolOnce.Do(func() {
		defaultBrPool = internal.NewPool(func() *bufio.Reader {
			return bufio.NewReaderSize(nil, c.ReadBufferSize)
		})
	})
	c.config = &Config{
		ParallelEnabled:     c.ParallelEnabled,
		ParallelGolimit:     c.ParallelGolimit,
		ReadMaxPayloadSize:  c.ReadMaxPayloadSize,
		ReadBufferSize:      c.ReadBufferSize,
		WriteMaxPayloadSize: c.WriteMaxPayloadSize,
		WriteBufferSize:     c.WriteBufferSize,
		CheckUtf8Enabled:    c.CheckUtf8Enabled,
		Recovery:            c.Recovery,
		Logger:              c.Logger,
		brPool:              defaultBrPool,
	}

	if c.PermessageDeflate.Enabled {
		if c.PermessageDeflate.ServerContextTakeover {
			c.config.cswPool = defaultDswCswPools[c.PermessageDeflate.ServerMaxWindowBits-8]
		}
		if c.PermessageDeflate.ClientContextTakeover {
			c.config.dswPool = defaultDswCswPools[c.PermessageDeflate.ClientMaxWindowBits-8]
		}
	}

	return c
}

// 获取通用配置
func (c *ServerOption) getConfig() *Config { return c.config }

type ClientOption struct {
	// 写缓冲区的大小, v1.4.5版本此参数被废弃
	// Deprecated: Size of the write buffer, v1.4.5 version of this parameter is deprecated
	WriteBufferSize int

	PermessageDeflate   PermessageDeflate
	ParallelEnabled     bool                // false
	ParallelGolimit     int                 // defaultParallelGolimit 8
	ReadMaxPayloadSize  int                 // defaultReadMaxPayloadSize 16MB
	ReadBufferSize      int                 // defaultReadBufferSize 4096
	WriteMaxPayloadSize int                 // defaultWriteMaxPayloadSize 16MB
	CheckUtf8Enabled    bool                // false
	Logger              Logger              // defaultLogger
	Recovery            func(logger Logger) // func(logger Logger) {}

	// 连接地址, 例如 wss://example.com/connect
	// server address, eg: wss://example.com/connect
	Addr string

	// 额外的请求头
	// extra request header
	RequestHeader http.Header

	// 握手超时时间
	HandshakeTimeout time.Duration

	// TLS设置
	TlsConfig *tls.Config

	// 拨号器
	// 默认是返回net.Dialer实例, 也可以用于设置代理.
	// The default is to return the net.Dialer instance
	// Can also be used to set a proxy, for example
	// NewDialer: func() (proxy.Dialer, error) {
	//		return proxy.SOCKS5("tcp", "127.0.0.1:1080", nil, nil)
	// },
	NewDialer func() (Dialer, error)

	// 创建session存储空间
	// 用于自定义SessionStorage实现
	// For custom SessionStorage implementations
	// func() SessionStorage { return newSmap() }
	NewSession func() SessionStorage
}

func initClientOption(c *ClientOption) *ClientOption {
	if c == nil {
		c = new(ClientOption)
	}
	if c.ReadMaxPayloadSize <= 0 {
		c.ReadMaxPayloadSize = defaultReadMaxPayloadSize
	}
	if c.ParallelGolimit <= 0 {
		c.ParallelGolimit = defaultParallelGolimit
	}
	if c.ReadBufferSize <= 0 {
		c.ReadBufferSize = defaultReadBufferSize
	}
	if c.WriteMaxPayloadSize <= 0 {
		c.WriteMaxPayloadSize = defaultWriteMaxPayloadSize
	}
	if c.WriteBufferSize <= 0 {
		c.WriteBufferSize = defaultWriteBufferSize
	}
	if c.HandshakeTimeout <= 0 {
		c.HandshakeTimeout = defaultHandshakeTimeout
	}
	if c.RequestHeader == nil {
		c.RequestHeader = http.Header{}
	}
	if c.NewDialer == nil {
		c.NewDialer = func() (Dialer, error) { return &net.Dialer{Timeout: defaultDialTimeout}, nil }
	}
	if c.NewSession == nil {
		c.NewSession = func() SessionStorage { return newSmap() }
	}
	if c.Logger == nil {
		c.Logger = defaultLogger
	}
	if c.Recovery == nil {
		c.Recovery = func(logger Logger) {}
	}
	if c.PermessageDeflate.Enabled {
		if c.PermessageDeflate.ServerMaxWindowBits < 8 || c.PermessageDeflate.ServerMaxWindowBits > 15 {
			c.PermessageDeflate.ServerMaxWindowBits = 15
		}
		if c.PermessageDeflate.ClientMaxWindowBits < 8 || c.PermessageDeflate.ClientMaxWindowBits > 15 {
			c.PermessageDeflate.ClientMaxWindowBits = 15
		}
		if c.PermessageDeflate.Threshold <= 0 {
			c.PermessageDeflate.Threshold = defaultCompressThreshold
		}
		if c.PermessageDeflate.Level == 0 {
			c.PermessageDeflate.Level = defaultCompressLevel
		}
		c.PermessageDeflate.PoolSize = 1
	}
	return c
}

func (c *ClientOption) getConfig() *Config {
	config := &Config{
		ParallelEnabled:     c.ParallelEnabled,
		ParallelGolimit:     c.ParallelGolimit,
		ReadMaxPayloadSize:  c.ReadMaxPayloadSize,
		ReadBufferSize:      c.ReadBufferSize,
		WriteMaxPayloadSize: c.WriteMaxPayloadSize,
		WriteBufferSize:     c.WriteBufferSize,
		CheckUtf8Enabled:    c.CheckUtf8Enabled,
		Recovery:            c.Recovery,
		Logger:              c.Logger,
	}
	return config
}
