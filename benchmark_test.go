package gws

import (
	"bufio"
	"bytes"
	"compress/flate"
	_ "embed"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"

	klauspost "github.com/klauspost/compress/flate"
	"github.com/lxzan/gws/internal"
)

//go:embed assets/github.json
var githubData []byte

type benchConn struct {
	net.TCPConn
}

func (m benchConn) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func BenchmarkConn_WriteMessage(b *testing.B) {
	b.Run("compress disabled", func(b *testing.B) {
		var upgrader = NewUpgrader(&BuiltinEventHandler{}, nil)
		var conn = &Conn{
			conn:   &benchConn{},
			config: upgrader.option.getConfig(),
		}
		for i := 0; i < b.N; i++ {
			_ = conn.WriteMessage(OpcodeText, githubData)
		}
	})

	b.Run("compress enabled", func(b *testing.B) {
		var upgrader = NewUpgrader(&BuiltinEventHandler{}, &ServerOption{
			PermessageDeflate: PermessageDeflate{
				Enabled:  true,
				PoolSize: 64,
			},
		})
		var config = upgrader.option.getConfig()
		var conn = &Conn{
			conn:     &benchConn{},
			pd:       PermessageDeflate{Enabled: true},
			config:   config,
			deflater: upgrader.deflaterPool.Select(),
		}
		for i := 0; i < b.N; i++ {
			_ = conn.WriteMessage(OpcodeText, githubData)
		}
	})
}

func BenchmarkConn_ReadMessage(b *testing.B) {
	var handler = &webSocketMocker{}
	handler.onMessage = func(socket *Conn, message *Message) { _ = message.Close() }

	b.Run("compress disabled", func(b *testing.B) {
		var upgrader = NewUpgrader(handler, nil)
		var conn1 = &Conn{
			isServer: false,
			conn:     &benchConn{},
			config:   upgrader.option.getConfig(),
		}
		var buf, _ = conn1.genFrame(OpcodeText, internal.Bytes(githubData), false)

		var reader = bytes.NewBuffer(buf.Bytes())
		var conn2 = &Conn{
			isServer: true,
			conn:     &benchConn{},
			br:       bufio.NewReader(reader),
			config:   upgrader.option.getConfig(),
			handler:  upgrader.eventHandler,
		}
		for i := 0; i < b.N; i++ {
			internal.BufferReset(reader, buf.Bytes())
			conn2.br.Reset(reader)
			_ = conn2.readMessage()
		}
	})

	b.Run("compress enabled", func(b *testing.B) {
		var upgrader = NewUpgrader(handler, &ServerOption{
			PermessageDeflate: PermessageDeflate{Enabled: true},
		})
		var config = upgrader.option.getConfig()
		var conn1 = &Conn{
			isServer: false,
			conn:     &benchConn{},
			pd:       upgrader.option.PermessageDeflate,
			config:   config,
			deflater: new(deflater),
		}
		conn1.deflater.initialize(false, conn1.pd, config.ReadMaxPayloadSize)
		var buf, _ = conn1.genFrame(OpcodeText, internal.Bytes(githubData), false)

		var reader = bytes.NewBuffer(buf.Bytes())
		var conn2 = &Conn{
			isServer: true,
			conn:     &benchConn{},
			br:       bufio.NewReader(reader),
			config:   upgrader.option.getConfig(),
			pd:       upgrader.option.PermessageDeflate,
			handler:  upgrader.eventHandler,
			deflater: upgrader.deflaterPool.Select(),
		}
		for i := 0; i < b.N; i++ {
			internal.BufferReset(reader, buf.Bytes())
			conn2.br.Reset(reader)
			_ = conn2.readMessage()
		}
	})
}

func BenchmarkStdCompress(b *testing.B) {
	fw, _ := flate.NewWriter(nil, flate.BestSpeed)
	contents := githubData
	buffer := bytes.NewBuffer(make([]byte, len(githubData)))
	for i := 0; i < b.N; i++ {
		buffer.Reset()
		fw.Reset(buffer)
		fw.Write(contents)
		fw.Flush()
	}
}

func BenchmarkKlauspostCompress(b *testing.B) {
	fw, _ := klauspost.NewWriter(nil, flate.BestSpeed)
	contents := githubData
	buffer := bytes.NewBuffer(make([]byte, len(githubData)))
	for i := 0; i < b.N; i++ {
		buffer.Reset()
		fw.Reset(buffer)
		fw.Write(contents)
		fw.Flush()
	}
}

func BenchmarkStdDeCompress(b *testing.B) {
	buffer := bytes.NewBuffer(make([]byte, 0, len(githubData)))
	fw, _ := flate.NewWriter(buffer, flate.BestSpeed)
	contents := githubData
	fw.Write(contents)
	fw.Flush()

	p := make([]byte, 4096)
	fr := flate.NewReader(nil)
	src := bytes.NewBuffer(nil)
	for i := 0; i < b.N; i++ {
		internal.BufferReset(src, buffer.Bytes())
		_, _ = src.Write(flateTail)
		resetter := fr.(flate.Resetter)
		_ = resetter.Reset(src, nil)
		io.CopyBuffer(io.Discard, fr, p)
	}
}

func BenchmarkKlauspostDeCompress(b *testing.B) {
	buffer := bytes.NewBuffer(make([]byte, 0, len(githubData)))
	fw, _ := klauspost.NewWriter(buffer, klauspost.BestSpeed)
	contents := githubData
	fw.Write(contents)
	fw.Flush()

	fr := klauspost.NewReader(nil)
	src := bytes.NewBuffer(nil)
	for i := 0; i < b.N; i++ {
		internal.BufferReset(src, buffer.Bytes())
		_, _ = src.Write(flateTail)
		resetter := fr.(klauspost.Resetter)
		_ = resetter.Reset(src, nil)
		fr.(io.WriterTo).WriteTo(io.Discard)
	}
}

func BenchmarkMask(b *testing.B) {
	var s1 = internal.AlphabetNumeric.Generate(1280)
	var s2 = s1
	var key [4]byte
	binary.LittleEndian.PutUint32(key[:4], internal.AlphabetNumeric.Uint32())
	for i := 0; i < b.N; i++ {
		internal.MaskXOR(s2, key[:4])
	}
}

func BenchmarkConcurrentMap_ReadWrite(b *testing.B) {
	const count = 1000000
	var cm = NewConcurrentMap[string, uint8](64)
	var keys = make([]string, 0, count)
	for i := 0; i < count; i++ {
		key := string(internal.AlphabetNumeric.Generate(16))
		keys = append(keys, key)
		cm.Store(key, 1)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var i = 0
		for pb.Next() {
			i++
			var key = keys[i%count]
			if i&15 == 0 {
				cm.Store(key, 1)
			} else {
				cm.Load(key)
			}
		}
	})
}

func BenchmarkConcurrentMap_ReadWrite2(b *testing.B) {
	const count = 1000000
	s := sync.Map{}
	//var cm = NewConcurrentMap[string, uint8](64)
	var keys = make([]string, 0, count)
	for i := 0; i < count; i++ {
		key := string(internal.AlphabetNumeric.Generate(16))
		keys = append(keys, key)
		s.Store(key, 1)
		//cm.Store(key, 1)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var i = 0
		for pb.Next() {
			i++
			var key = keys[i%count]
			if i&15 == 0 {
				s.Store(key, 1)
			} else {
				s.Load(key)
			}
		}
	})
}
