package fingerprint

import (
	"sync/atomic"
	"time"
)

var (
	clientTimeout  atomic.Int64
	dialTimeout    atomic.Int64
	verifyUpstream atomic.Bool
)

func init() {
	clientTimeout.Store(int64(30 * time.Second))
	dialTimeout.Store(int64(10 * time.Second))
	verifyUpstream.Store(true)
}

func ClientTimeout() time.Duration { return time.Duration(clientTimeout.Load()) }

func SetClientTimeout(d time.Duration) { clientTimeout.Store(int64(d)) }

func DialTimeout() time.Duration { return time.Duration(dialTimeout.Load()) }

func SetDialTimeout(d time.Duration) { dialTimeout.Store(int64(d)) }

func VerifyUpstream() bool { return verifyUpstream.Load() }

func SetVerifyUpstream(on bool) { verifyUpstream.Store(on) }
