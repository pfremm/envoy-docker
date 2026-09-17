package xds

import (
	"testing"

	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	bufferv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/buffer/v3"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/bryanpfremm/envoy-control-plane/internal/model"
)

func TestApplyRouteMiddlewares_Retry(t *testing.T) {
	tests := []struct {
		name      string
		mw        []model.Middleware
		wantRetry bool
	}{
		{
			name: "retry middleware sets retry policy",
			mw: []model.Middleware{
				{
					Name: "test-retry",
					Retry: &model.RetryMiddleware{
						Attempts:      3,
						PerTryTimeout: "1s",
						RetryOn:       "5xx,reset",
					},
				},
			},
			wantRetry: true,
		},
		{
			name:      "no retry middleware",
			mw:        []model.Middleware{},
			wantRetry: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route := &routev3.Route{
				Action: &routev3.Route_Route{
					Route: &routev3.RouteAction{},
				},
			}

			if err := applyRouteMiddlewares(route, tt.mw); err != nil {
				t.Fatalf("applyRouteMiddlewares() error = %v", err)
			}

			ra := route.GetRoute()
			if tt.wantRetry {
				if ra.RetryPolicy == nil {
					t.Fatal("expected retry policy, got nil")
				}
				if ra.RetryPolicy.RetryOn != "5xx,reset" {
					t.Errorf("RetryOn = %q, want \"5xx,reset\"", ra.RetryPolicy.RetryOn)
				}
				if ra.RetryPolicy.NumRetries.GetValue() != 3 {
					t.Errorf("NumRetries = %d, want 3", ra.RetryPolicy.NumRetries.GetValue())
				}
				want := durationpb.New(1000000000) // 1s
				if ra.RetryPolicy.PerTryTimeout.Seconds != want.Seconds {
					t.Errorf("PerTryTimeout = %v, want %v", ra.RetryPolicy.PerTryTimeout, want)
				}
			} else {
				if ra.RetryPolicy != nil {
					t.Errorf("expected no retry policy, got %+v", ra.RetryPolicy)
				}
			}
		})
	}
}

func TestApplyRouteMiddlewares_Buffering(t *testing.T) {
	tests := []struct {
		name                string
		mw                  []model.Middleware
		wantBufferPerRoute  bool
		wantMaxRequestBytes uint32
	}{
		{
			name: "buffering middleware sets buffer config",
			mw: []model.Middleware{
				{
					Name: "test-buffer",
					Buffering: &model.BufferingMiddleware{
						MaxRequestBytes: 1048576,
					},
				},
			},
			wantBufferPerRoute:  true,
			wantMaxRequestBytes: 1048576,
		},
		{
			name:               "no buffering middleware",
			mw:                 []model.Middleware{},
			wantBufferPerRoute: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route := &routev3.Route{
				Action: &routev3.Route_Route{
					Route: &routev3.RouteAction{},
				},
			}

			if err := applyRouteMiddlewares(route, tt.mw); err != nil {
				t.Fatalf("applyRouteMiddlewares() error = %v", err)
			}

			cfg, ok := route.TypedPerFilterConfig[bufferFilterName]
			if tt.wantBufferPerRoute {
				if !ok {
					t.Fatal("expected buffer per-route config, got none")
				}
				var bpr bufferv3.BufferPerRoute
				if err := cfg.UnmarshalTo(&bpr); err != nil {
					t.Fatalf("failed to unmarshal buffer config: %v", err)
				}
				if b := bpr.GetBuffer(); b != nil {
					if b.MaxRequestBytes.GetValue() != tt.wantMaxRequestBytes {
						t.Errorf("MaxRequestBytes = %d, want %d", b.MaxRequestBytes.GetValue(), tt.wantMaxRequestBytes)
					}
				} else {
					t.Error("expected buffer override, got nil")
				}
			} else {
				if ok {
					t.Errorf("expected no buffer per-route config, got %+v", cfg)
				}
			}
		})
	}
}

func TestApplyRouteMiddlewares_RetryAndBufferingComposed(t *testing.T) {
	route := &routev3.Route{
		Action: &routev3.Route_Route{
			Route: &routev3.RouteAction{},
		},
	}

	mw := []model.Middleware{
		{
			Name: "retry",
			Retry: &model.RetryMiddleware{
				Attempts:      5,
				PerTryTimeout: "500ms",
				RetryOn:       "5xx",
			},
		},
		{
			Name: "buffer",
			Buffering: &model.BufferingMiddleware{
				MaxRequestBytes: 2048,
			},
		},
	}

	if err := applyRouteMiddlewares(route, mw); err != nil {
		t.Fatalf("applyRouteMiddlewares() error = %v", err)
	}

	// Check retry
	ra := route.GetRoute()
	if ra.RetryPolicy == nil {
		t.Fatal("expected retry policy")
	}
	if ra.RetryPolicy.RetryOn != "5xx" {
		t.Errorf("RetryOn = %q, want \"5xx\"", ra.RetryPolicy.RetryOn)
	}

	// Check buffering
	cfg, ok := route.TypedPerFilterConfig[bufferFilterName]
	if !ok {
		t.Fatal("expected buffer per-route config")
	}
	var bpr bufferv3.BufferPerRoute
	if err := cfg.UnmarshalTo(&bpr); err != nil {
		t.Fatalf("failed to unmarshal buffer config: %v", err)
	}
	if b := bpr.GetBuffer(); b == nil || b.MaxRequestBytes.GetValue() != 2048 {
		t.Errorf("buffer config incorrect: got %+v", b)
	}
}

func TestUnsupportedMiddlewareRejectedAtValidation(t *testing.T) {
	// This test verifies that unsupported settings are caught at model validation
	// rather than silently ignored at xDS time.
	tests := []struct {
		name    string
		mw      model.Middleware
		wantErr bool
	}{
		{
			name: "buffering with retryexpression rejected",
			mw: model.Middleware{
				Name: "bad-buffer",
				Buffering: &model.BufferingMiddleware{
					MaxRequestBytes: 1024,
					RetryExpression: "unsupported",
				},
			},
			wantErr: true,
		},
		{
			name: "valid buffering accepted",
			mw: model.Middleware{
				Name: "good-buffer",
				Buffering: &model.BufferingMiddleware{
					MaxRequestBytes: 1024,
				},
			},
			wantErr: false,
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
