package kernel

import (
	"context"
	"strconv"
	"time"

	"github.com/asscor/asscor/internal/logger"
)

type HandlerFunc func(ctx context.Context, service, method string, payload []byte) ([]byte, error)

type Interceptor func(ctx context.Context, service, method string, payload []byte, handler HandlerFunc) ([]byte, error)

type InterceptorChain struct {
	interceptors []Interceptor
}

func NewInterceptorChain() *InterceptorChain {
	return &InterceptorChain{}
}

func (c *InterceptorChain) Use(interceptors ...Interceptor) {
	c.interceptors = append(c.interceptors, interceptors...)
}

func (c *InterceptorChain) Then(handler HandlerFunc) HandlerFunc {
	for i := len(c.interceptors) - 1; i >= 0; i-- {
		ic := c.interceptors[i]
		next := handler
		handler = func(ctx context.Context, service, method string, payload []byte) ([]byte, error) {
			return ic(ctx, service, method, payload, next)
		}
	}
	return handler
}

func (c *InterceptorChain) Interceptors() []Interceptor {
	return c.interceptors
}

type InterceptorEvent struct {
	Timestamp   time.Time
	ClientAddr  string
	Service     string
	Method      string
	RequestSize int
	Success     bool
	Duration    time.Duration
	Error       string
}

type InterceptorHooks struct {
	OnRejected func(service, method string, reason string)
	OnBroken   func(service, method string)
	OnAudit    func(event InterceptorEvent)
}

func DefaultInterceptorHooks() *InterceptorHooks {
	return &InterceptorHooks{
		OnRejected: func(service, method, reason string) {
			logger.WithComponent("interceptor").Warn("request rejected", "service", service, "method", method, "reason", reason)
		},
		OnBroken: func(service, method string) {
			logger.WithComponent("interceptor").Warn("circuit open", "service", service, "method", method)
		},
		OnAudit: func(event InterceptorEvent) {
			status := "OK"
			if !event.Success {
				status = "ERR"
			}
			logger.WithComponent("audit").Info("audit log",
				"timestamp", event.Timestamp.Format(time.RFC3339),
				"service", event.Service,
				"method", event.Method,
				"client", event.ClientAddr,
				"size", event.RequestSize,
				"duration", event.Duration.Round(time.Microsecond).String(),
				"status", status,
				"error", event.Error,
			)
		},
	}
}

type InterceptorConfig struct {
	RateLimitEnabled      bool
	RateLimitPerSec       float64
	RateLimitBurst        int
	CircuitBreakerEnabled bool
	CircuitBreakerRatio   float64
	CircuitBreakerMinReq  int
	CircuitBreakerTimeout time.Duration
	AuditLogEnabled       bool
	Hooks                 *InterceptorHooks
}

func DefaultInterceptorConfig() InterceptorConfig {
	return InterceptorConfig{
		RateLimitEnabled:      false,
		RateLimitPerSec:       100.0,
		RateLimitBurst:        50,
		CircuitBreakerEnabled: false,
		CircuitBreakerRatio:   0.5,
		CircuitBreakerMinReq:  10,
		CircuitBreakerTimeout: 30 * time.Second,
		AuditLogEnabled:       true,
		Hooks:                 DefaultInterceptorHooks(),
	}
}

type Interceptors struct {
	Chain              *InterceptorChain
	RateLimiter        *RateLimiter
	CircuitBreaker     *CircuitBreaker
	AuditLog           *AuditLogInterceptor
	config             InterceptorConfig
}

func NewInterceptors(cfg InterceptorConfig) *Interceptors {
	ic := &Interceptors{
		Chain:  NewInterceptorChain(),
		config: cfg,
	}

	if cfg.AuditLogEnabled {
		al := NewAuditLogInterceptor(cfg.Hooks.OnAudit)
		ic.AuditLog = al
		ic.Chain.Use(al.Interceptor())
	}

	if cfg.RateLimitEnabled {
		rl := NewRateLimiter(cfg.RateLimitPerSec, cfg.RateLimitBurst, cfg.Hooks.OnRejected)
		ic.RateLimiter = rl
		ic.Chain.Use(rl.Interceptor())
	}

	if cfg.CircuitBreakerEnabled {
		cb := NewCircuitBreaker(CircuitBreakerConfig{
			FailureRatio:  cfg.CircuitBreakerRatio,
			MinRequests:   cfg.CircuitBreakerMinReq,
			Timeout:       cfg.CircuitBreakerTimeout,
			OnStateChange: cfg.Hooks.OnBroken,
		})
		ic.CircuitBreaker = cb
		ic.Chain.Use(cb.Interceptor())
	}

	return ic
}

func ResolveInterceptorConfig(cfg map[string]string) InterceptorConfig {
	ic := DefaultInterceptorConfig()

	if v, ok := cfg["interceptor.rate_limit_enabled"]; ok {
		ic.RateLimitEnabled = v == "true" || v == "1"
	}
	if v, ok := cfg["interceptor.rate_limit_per_sec"]; ok {
		if f, err := parseFloat64(v); err == nil && f > 0 {
			ic.RateLimitPerSec = f
		} else if err != nil {
			logger.WithComponent("interceptor").Warn("invalid config value", "key", "rate_limit_per_sec", "value", v, "error", err)
		}
	}
	if v, ok := cfg["interceptor.rate_limit_burst"]; ok {
		if i, err := parseInt(v); err == nil && i > 0 {
			ic.RateLimitBurst = i
		} else if err != nil {
			logger.WithComponent("interceptor").Warn("invalid config value", "key", "rate_limit_burst", "value", v, "error", err)
		}
	}
	if v, ok := cfg["interceptor.circuit_breaker_enabled"]; ok {
		ic.CircuitBreakerEnabled = v == "true" || v == "1"
	}
	if v, ok := cfg["interceptor.circuit_breaker_ratio"]; ok {
		if f, err := parseFloat64(v); err == nil && f > 0 && f <= 1.0 {
			ic.CircuitBreakerRatio = f
		} else if err != nil {
			logger.WithComponent("interceptor").Warn("invalid config value", "key", "circuit_breaker_ratio", "value", v, "error", err)
		}
	}
	if v, ok := cfg["interceptor.circuit_breaker_min_req"]; ok {
		if i, err := parseInt(v); err == nil && i > 0 {
			ic.CircuitBreakerMinReq = i
		} else if err != nil {
			logger.WithComponent("interceptor").Warn("invalid config value", "key", "circuit_breaker_min_req", "value", v, "error", err)
		}
	}
	if v, ok := cfg["interceptor.circuit_breaker_timeout_s"]; ok {
		if i, err := parseInt(v); err == nil && i > 0 {
			ic.CircuitBreakerTimeout = time.Duration(i) * time.Second
		} else if err != nil {
			logger.WithComponent("interceptor").Warn("invalid config value", "key", "circuit_breaker_timeout_s", "value", v, "error", err)
		}
	}
	if v, ok := cfg["interceptor.audit_log_enabled"]; ok {
		ic.AuditLogEnabled = v == "true" || v == "1"
	}

	return ic
}

func (ic *Interceptors) Stop() {
	if ic.RateLimiter != nil {
		ic.RateLimiter.Stop()
	}
	if ic.CircuitBreaker != nil {
		ic.CircuitBreaker.Stop()
	}
}

func parseFloat64(s string) (float64, error) {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, err
	}
	return f, nil
}

func parseInt(s string) (int, error) {
	i, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	return i, nil
}