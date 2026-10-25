package setup

import "testing"

// checkSSLMode 是 Web 向导 test-db 与 install 提交两条路径共用的取值校验。
// 两处曾使用不同的集合，导致 MySQL 下连接测试放行的 TLS 取值在最后一步被拒。
func TestCheckSSLModeByDriver(t *testing.T) {
	tests := []struct {
		driver string
		mode   string
		ok     bool
	}{
		{"mysql", "disable", true},
		{"mysql", "prefer", true},
		{"mysql", "preferred", true},
		{"mysql", "require", true},
		{"mysql", "skip-verify", true},
		{"mysql", "verify-ca", true},
		{"mysql", "verify-full", true},
		{"mysql", "false", true},
		{"mysql", "true", true},
		{"MySQL ", "PREFERRED", true},
		{"mysql", "allow", false},
		{"mysql", "verify", false},
		{"postgres", "disable", true},
		{"postgres", "require", true},
		{"postgres", "verify-ca", true},
		{"postgres", "verify-full", true},
		{"postgres", "preferred", false},
		{"postgres", "skip-verify", false},
		{"", "disable", true},
		{"", "preferred", false},
	}
	for _, tt := range tests {
		ok, msg := checkSSLMode(tt.driver, tt.mode)
		if ok != tt.ok {
			t.Errorf("checkSSLMode(%q, %q) = %v (msg %q), want %v", tt.driver, tt.mode, ok, msg, tt.ok)
		}
	}
}
