package util

import (
	"context"
	"maps"
)

type contextKey struct{}

type ContextMeta = map[string]string

func AddContextMeta(ctx context.Context, m ContextMeta) context.Context {
	if len(m) == 0 {
		return ctx
	}
	if v, _ := ctx.Value(contextKey{}).(ContextMeta); v != nil {
		if maps.Equal(v, m) {
			return ctx
		}
		v = maps.Clone(v)
		maps.Copy(v, m)
		m = v
	}
	return context.WithValue(ctx, contextKey{}, m)
}

func GetContextMeta(ctx context.Context) ContextMeta {
	if v, _ := ctx.Value(contextKey{}).(ContextMeta); len(v) > 0 {
		return maps.Clone(v)
	}
	return ContextMeta{}
}
