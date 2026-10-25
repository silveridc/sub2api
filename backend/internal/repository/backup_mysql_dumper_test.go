package repository

import (
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

func dbCfg(sslmode string) *config.DatabaseConfig {
	return &config.DatabaseConfig{
		Driver:  "mysql",
		Host:    "127.0.0.1",
		Port:    3306,
		User:    "sub2api",
		DBName:  "sub2api",
		SSLMode: sslmode,
	}
}

// mysqldump 没有 --skip-definer（那是 MySQL Shell 的参数），带上它会让备份直接
// 以 "unknown option" 失败；表空间导出需要 PROCESS 权限，应用账号一般没有。
func TestMySQLDumpArgs(t *testing.T) {
	args := mysqlDumpArgs(dbCfg("require"))

	require.NotContains(t, args, "--skip-definer")
	require.Contains(t, args, "--triggers")
	require.Contains(t, args, "--no-tablespaces")
	require.Contains(t, args, "--single-transaction")
	require.Contains(t, args, "--ssl-mode=REQUIRED")
	require.Contains(t, args, "sub2api")
}

func TestMySQLRestoreArgs(t *testing.T) {
	require.Equal(t,
		[]string{"--host=127.0.0.1", "--port=3306", "--user=sub2api", "sub2api", "--ssl-mode=REQUIRED"},
		mysqlRestoreArgs(dbCfg("require")),
	)
}

// 备份/恢复的加密档位必须与应用连接一致。
func TestMySQLClientTLSArgFollowsSSLMode(t *testing.T) {
	tests := []struct {
		sslmode string
		want    string
	}{
		{"disable", "--ssl-mode=DISABLED"},
		{"prefer", "--ssl-mode=PREFERRED"},
		{"preferred", "--ssl-mode=PREFERRED"},
		{"require", "--ssl-mode=REQUIRED"},
		{"skip-verify", "--ssl-mode=REQUIRED"},
		{"verify-ca", "--ssl-mode=VERIFY_IDENTITY"},
		{"verify-full", "--ssl-mode=VERIFY_IDENTITY"},
	}
	for _, tt := range tests {
		require.Contains(t, mysqlDumpArgs(dbCfg(tt.sslmode)), tt.want, "sslmode %q", tt.sslmode)
		require.Contains(t, mysqlRestoreArgs(dbCfg(tt.sslmode)), tt.want, "sslmode %q", tt.sslmode)
	}

	// 非法取值不追加参数（由 config 校验拦截，不能在这里猜一个档位）。
	for _, arg := range mysqlDumpArgs(dbCfg("allow")) {
		require.NotContains(t, arg, "--ssl-mode")
	}
}
