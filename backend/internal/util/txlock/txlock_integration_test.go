//go:build integration_mysql

package txlock

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	dbent "github.com/Wei-Shaw/sub2api/ent"
	_ "github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/require"
)

// lockIsFree 用独立连接观测命名锁是否已释放（1=空闲）。
func lockIsFree(t *testing.T, observer *sql.DB, name string) int {
	t.Helper()
	var free int
	require.NoError(t, observer.QueryRow("SELECT IS_FREE_LOCK(?)", name).Scan(&free))
	return free
}

func openMySQLPair(t *testing.T) (*dbent.Client, *sql.DB) {
	t.Helper()
	dsn := os.Getenv("SUB2API_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("SUB2API_TEST_MYSQL_DSN not set")
	}
	clientDB, err := sql.Open("mysql", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = clientDB.Close() })
	observerDB, err := sql.Open("mysql", dsn)
	require.NoError(t, err)
	observerDB.SetMaxOpenConns(2)
	t.Cleanup(func() { _ = observerDB.Close() })
	return dbent.NewClient(dbent.Driver(entsql.OpenDB(dialect.MySQL, clientDB))), observerDB
}

// 提交与回滚两条路径都必须释放锁：MySQL 的 GET_LOCK 不随事务结束自动释放，
// 残留会把后续会话挡在超时上。
func TestAcquireReleasesOnCommit(t *testing.T) {
	client, observer := openMySQLPair(t)
	ctx := context.Background()
	name := fmt.Sprintf("sub2api_txlock_test_%d", time.Now().UnixNano())

	tx, err := client.Tx(ctx)
	require.NoError(t, err)
	require.NoError(t, Acquire(ctx, tx, name))
	require.Equal(t, 0, lockIsFree(t, observer, name), "持锁期间锁不应空闲")
	require.NoError(t, tx.Commit())
	require.Equal(t, 1, lockIsFree(t, observer, name), "提交后应释放锁")
}

func TestAcquireReleasesOnRollback(t *testing.T) {
	client, observer := openMySQLPair(t)
	ctx := context.Background()
	name := fmt.Sprintf("sub2api_txlock_test_%d", time.Now().UnixNano())

	tx, err := client.Tx(ctx)
	require.NoError(t, err)
	require.NoError(t, Acquire(ctx, tx, name))
	require.Equal(t, 0, lockIsFree(t, observer, name))
	require.NoError(t, tx.Rollback())
	require.Equal(t, 1, lockIsFree(t, observer, name), "回滚后应释放锁")
}

// 同一连接重复取同名锁会累计计数（MySQL 语义），每次 Acquire 各注册一次释放，计数保持平衡。
func TestAcquireTwiceReleasesBothCounts(t *testing.T) {
	client, observer := openMySQLPair(t)
	ctx := context.Background()
	name := fmt.Sprintf("sub2api_txlock_test_%d", time.Now().UnixNano())

	tx, err := client.Tx(ctx)
	require.NoError(t, err)
	require.NoError(t, Acquire(ctx, tx, name))
	require.NoError(t, Acquire(ctx, tx, name))
	require.NoError(t, tx.Commit())
	require.Equal(t, 1, lockIsFree(t, observer, name), "两次取锁应被两次释放抵消")
}
