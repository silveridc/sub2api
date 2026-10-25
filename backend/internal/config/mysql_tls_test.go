package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeMySQLTLSMode(t *testing.T) {
	tests := []struct {
		sslmode string
		want    string
	}{
		{"", ""},
		{"disable", ""},
		{"FALSE", ""},
		{"prefer", "preferred"},
		{"  Preferred ", "preferred"},
		{"require", "skip-verify"},
		{"skip-verify", "skip-verify"},
		{"verify-ca", "true"},
		{"verify-full", "true"},
		{"true", "true"},
	}
	for _, tt := range tests {
		got, valid := NormalizeMySQLTLSMode(tt.sslmode)
		require.True(t, valid, "sslmode %q must be accepted", tt.sslmode)
		require.Equal(t, tt.want, got, "sslmode %q", tt.sslmode)
	}
}

func TestNormalizeMySQLTLSModeRejectsUnknown(t *testing.T) {
	// 非法取值必须报错，不能被静默降级成明文连接。
	for _, sslmode := range []string{"allow", "verify", "tls", "skipverify", "required", "0"} {
		_, valid := NormalizeMySQLTLSMode(sslmode)
		require.False(t, valid, "sslmode %q must be rejected", sslmode)
	}
}

func TestValidMySQLTLSModesMatchesMapping(t *testing.T) {
	// 防漂移：提示列表里的每个取值都必须能被映射表接受。
	for _, mode := range ValidMySQLTLSModes() {
		_, valid := NormalizeMySQLTLSMode(mode)
		require.True(t, valid, "listed sslmode %q is not in the mapping table", mode)
	}
	require.NotContains(t, ValidMySQLTLSModes(), "")
}

func TestValidateMySQLSSLMode(t *testing.T) {
	resetViperWithJWTSecret(t)
	cfg, err := Load()
	require.NoError(t, err)

	cfg.Database.Driver = "mysql"
	// sslmode 缺省时 viper 给的是 PG 惯用值 prefer（deploy/config.example.yaml 同值），
	// MySQL 驱动下必须照常通过校验。
	cfg.Database.SSLMode = "prefer"
	require.NoError(t, cfg.Validate())

	cfg.Database.SSLMode = "allow"
	require.ErrorContains(t, cfg.Validate(), "database.sslmode")

	// PG 驱动不受 MySQL 取值集合约束。
	cfg.Database.Driver = "postgres"
	cfg.Database.SSLMode = "allow"
	require.NoError(t, cfg.Validate())
}

func TestMySQLClientTLSMode(t *testing.T) {
	// MySQL 客户端工具（mysqldump / mysql）的 --ssl-mode 必须与驱动档位同档。
	tests := []struct {
		sslmode string
		want    string
	}{
		{"", "DISABLED"},
		{"disable", "DISABLED"},
		{"prefer", "PREFERRED"},
		{"preferred", "PREFERRED"},
		{"require", "REQUIRED"},
		{"skip-verify", "REQUIRED"},
		{"verify-ca", "VERIFY_IDENTITY"},
		{"verify-full", "VERIFY_IDENTITY"},
		{"true", "VERIFY_IDENTITY"},
	}
	for _, tt := range tests {
		got, ok := MySQLClientTLSMode(tt.sslmode)
		require.True(t, ok, "sslmode %q must be accepted", tt.sslmode)
		require.Equal(t, tt.want, got, "sslmode %q", tt.sslmode)
	}

	_, ok := MySQLClientTLSMode("allow")
	require.False(t, ok)
}

func TestMySQLDSNCarriesTLSMode(t *testing.T) {
	base := DatabaseConfig{
		Driver:   "mysql",
		Host:     "127.0.0.1",
		Port:     3306,
		User:     "u",
		Password: "p",
		DBName:   "db",
	}

	tests := []struct {
		sslmode string
		want    string
	}{
		{"disable", ""},
		{"prefer", "tls=preferred"},
		{"require", "tls=skip-verify"},
		{"verify-full", "tls=true"},
	}
	for _, tt := range tests {
		d := base
		d.SSLMode = tt.sslmode
		dsn, err := d.MySQLDSN("UTC")
		require.NoError(t, err)
		if tt.want == "" {
			require.NotContains(t, dsn, "tls=")
			continue
		}
		require.Contains(t, dsn, tt.want, "sslmode %q", tt.sslmode)
	}
}
