package kernel

import (
	"context"
	"time"
)

type AuditLogInterceptor struct {
	onAudit func(event InterceptorEvent)
}

func NewAuditLogInterceptor(onAudit func(event InterceptorEvent)) *AuditLogInterceptor {
	return &AuditLogInterceptor{
		onAudit: onAudit,
	}
}

func (a *AuditLogInterceptor) Interceptor() Interceptor {
	return func(ctx context.Context, service, method string, payload []byte, handler HandlerFunc) ([]byte, error) {
		start := time.Now()
		resp, err := handler(ctx, service, method, payload)
		elapsed := time.Since(start)

		if a.onAudit != nil {
			clientAddr, _ := ctx.Value(CtxKey("client_addr")).(string)

			errStr := ""
			if err != nil {
				errStr = err.Error()
			}

			a.onAudit(InterceptorEvent{
				Timestamp:   start,
				ClientAddr:  clientAddr,
				Service:     service,
				Method:      method,
				RequestSize: len(payload),
				Success:     err == nil,
				Duration:    elapsed,
				Error:       errStr,
			})
		}

		return resp, err
	}
}
