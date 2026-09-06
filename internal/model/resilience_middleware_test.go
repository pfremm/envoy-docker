package model

import (
	"testing"
)

func TestRetryMiddlewareValidation(t *testing.T) {
	tests := []struct {
		name    string
		mw      Middleware
		wantErr bool
	}{
		{
			name: "valid retry",
			mw: Middleware{
				Name: "test-retry",
				Retry: &RetryMiddleware{
					Attempts:      3,
					PerTryTimeout: "1s",
					RetryOn:       "5xx,reset",
				},
			},
			wantErr: false,
		},
		{
			name: "zero attempts rejected",
			mw: Middleware{
				Name: "bad-retry",
				Retry: &RetryMiddleware{
					Attempts:      0,
					PerTryTimeout: "1s",
					RetryOn:       "5xx",
				},
			},
			wantErr: true,
		},
		{
			name: "missing pertrytimeout rejected",
			mw: Middleware{
				Name: "bad-retry",
				Retry: &RetryMiddleware{
					Attempts: 3,
					RetryOn:  "5xx",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid duration rejected",
			mw: Middleware{
				Name: "bad-retry",
				Retry: &RetryMiddleware{
					Attempts:      3,
					PerTryTimeout: "notaduration",
					RetryOn:       "5xx",
				},
			},
			wantErr: true,
		},
		{
			name: "empty retryon rejected",
			mw: Middleware{
				Name: "bad-retry",
				Retry: &RetryMiddleware{
					Attempts:      3,
					PerTryTimeout: "1s",
					RetryOn:       "",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.mw.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBufferingMiddlewareValidation(t *testing.T) {
	tests := []struct {
		name    string
		mw      Middleware
		wantErr bool
	}{
		{
			name: "valid buffering",
			mw: Middleware{
				Name: "test-buffer",
				Buffering: &BufferingMiddleware{
					MaxRequestBytes: 1048576,
				},
			},
			wantErr: false,
		},
		{
			name: "retryexpression rejected",
			mw: Middleware{
				Name: "bad-buffer",
				Buffering: &BufferingMiddleware{
					MaxRequestBytes: 1048576,
					RetryExpression: "someexpr",
				},
			},
			wantErr: true,
		},
		{
			name: "no thresholds rejected",
			mw: Middleware{
				Name:      "bad-buffer",
				Buffering: &BufferingMiddleware{},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.mw.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCircuitBreakerMiddlewareValidation(t *testing.T) {
	tests := []struct {
		name    string
		mw      Middleware
		wantErr bool
	}{
		{
			name: "valid circuit breaker",
			mw: Middleware{
				Name: "test-cb",
				CircuitBreaker: &CircuitBreakerMiddleware{
					MaxConnections: 100,
				},
			},
			wantErr: false,
		},
		{
			name: "no thresholds rejected",
			mw: Middleware{
				Name:           "bad-cb",
				CircuitBreaker: &CircuitBreakerMiddleware{},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.mw.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestErrorsMiddlewareValidation(t *testing.T) {
	tests := []struct {
		name    string
		mw      Middleware
		wantErr bool
	}{
		{
			name: "valid error handler",
			mw: Middleware{
				Name: "test-errors",
				Errors: &ErrorsMiddleware{
					Status:  []string{"404", "500-599"},
					Service: "error-service",
					Query:   "/error",
				},
			},
			wantErr: false,
		},
		{
			name: "missing status rejected",
			mw: Middleware{
				Name: "bad-errors",
				Errors: &ErrorsMiddleware{
					Service: "error-service",
				},
			},
			wantErr: true,
		},
		{
			name: "missing service rejected",
			mw: Middleware{
				Name: "bad-errors",
				Errors: &ErrorsMiddleware{
					Status: []string{"404"},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid status code rejected",
			mw: Middleware{
				Name: "bad-errors",
				Errors: &ErrorsMiddleware{
					Status:  []string{"999"},
					Service: "error-service",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid status range rejected",
			mw: Middleware{
				Name: "bad-errors",
				Errors: &ErrorsMiddleware{
					Status:  []string{"500-400"},
					Service: "error-service",
				},
			},
			wantErr: true,
		},
		{
			name: "query without leading slash rejected",
			mw: Middleware{
				Name: "bad-errors",
				Errors: &ErrorsMiddleware{
					Status:  []string{"404"},
					Service: "error-service",
					Query:   "error",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.mw.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGRPCWebMiddlewareValidation(t *testing.T) {
	tests := []struct {
		name    string
		mw      Middleware
		wantErr bool
	}{
		{
			name: "valid grpcweb",
			mw: Middleware{
				Name:    "test-grpcweb",
				GRPCWeb: &GRPCWebMiddleware{Enabled: true},
			},
			wantErr: false,
		},
		{
			name: "enabled=false rejected",
			mw: Middleware{
				Name:    "bad-grpcweb",
				GRPCWeb: &GRPCWebMiddleware{Enabled: false},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.mw.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCompressMiddlewareValidation(t *testing.T) {
	tests := []struct {
		name    string
		mw      Middleware
		wantErr bool
	}{
		{
			name: "valid compression",
			mw: Middleware{
				Name: "test-compress",
				Compress: &CompressMiddleware{
					MinResponseBytes: 1024,
					ContentTypes:     []string{"text/html", "application/json"},
				},
			},
			wantErr: false,
		},
		{
			name: "empty content type rejected",
			mw: Middleware{
				Name: "bad-compress",
				Compress: &CompressMiddleware{
					ContentTypes: []string{"text/html", ""},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.mw.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
