package fingerprint

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"golang.org/x/net/proxy"
)

var (
	upstreamOpen    atomic.Int64
	upstreamDialing atomic.Int64
	upstreamOpened  atomic.Int64
	upstreamFailed  atomic.Int64
)

func UpstreamStats() (open, dialing, opened, failed int64) {
	return upstreamOpen.Load(), upstreamDialing.Load(), upstreamOpened.Load(), upstreamFailed.Load()
}

type countingDialer struct{ inner proxy.ContextDialer }

func (d countingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	upstreamDialing.Add(1)
	conn, err := d.inner.DialContext(ctx, network, addr)
	upstreamDialing.Add(-1)

	if err != nil {
		upstreamFailed.Add(1)
		return nil, err
	}

	upstreamOpen.Add(1)
	upstreamOpened.Add(1)
	return &countedConn{Conn: conn}, nil
}

func (d countingDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

type countedConn struct {
	net.Conn
	once sync.Once
}

func (c *countedConn) Close() error {
	c.once.Do(func() { upstreamOpen.Add(-1) })
	return c.Conn.Close()
}

func countingProxyDialer(proxyURL string) tls_client.ProxyDialerFactory {
	return func(_ string, timeout time.Duration, localAddr *net.TCPAddr, connectHeaders fhttp.Header, logger tls_client.Logger) (proxy.ContextDialer, error) {
		if logger == nil {
			logger = tls_client.NewNoopLogger()
		}

		inner, err := tls_client.NewConnectDialer(
			proxyURL, timeout, localAddr,
			net.Dialer{Timeout: DialTimeout(), KeepAlive: 30 * time.Second},
			connectHeaders, logger,
		)
		if err != nil {
			return nil, err
		}
		return countingDialer{inner: inner}, nil
	}
}
