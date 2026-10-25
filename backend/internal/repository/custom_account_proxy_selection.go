package repository

import (
	"context"
	"fmt"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/util/txlock"
)

// proxyLeastUsedLockNameMySQL 是 MySQL 方言下最空闲代理选择的事务级命名锁名。
const proxyLeastUsedLockNameMySQL = "sub2api:proxy_least_used"

// SelectAccountProxy 在数据库内选出单个 ID，不把整个代理池或密码载入应用。
// 最空闲选择持有事务级锁到绑定提交，防止并发推送全部观察到同一份空闲计数。
func (r *proxyRepository) SelectAccountProxy(ctx context.Context, mode string) (int64, error) {
	tx := dbent.TxFromContext(ctx)
	if tx == nil {
		return 0, fmt.Errorf("代理选择需要写事务")
	}
	if IsMySQL() {
		return selectAccountProxyMySQL(ctx, tx, mode)
	}
	client := tx.Client()
	query := `SELECT p.id FROM proxies p WHERE p.deleted_at IS NULL AND p.status='active' AND (p.expires_at IS NULL OR p.expires_at>NOW()) ORDER BY random() LIMIT 1`
	switch mode {
	case "random":
	case "least_used":
		if _, err := client.ExecContext(ctx, `SELECT pg_advisory_xact_lock(742319830125)`); err != nil {
			return 0, err
		}
		query = `WITH bindings AS (
   SELECT a.id AS account_id,a.proxy_id FROM accounts a WHERE a.deleted_at IS NULL AND a.proxy_id IS NOT NULL
  ), counts AS (SELECT proxy_id,COUNT(*) AS n FROM bindings GROUP BY proxy_id)
  SELECT p.id FROM proxies p LEFT JOIN counts c ON c.proxy_id=p.id
  WHERE p.deleted_at IS NULL AND p.status='active' AND (p.expires_at IS NULL OR p.expires_at>NOW())
  ORDER BY COALESCE(c.n,0),p.id LIMIT 1`
	default:
		return 0, fmt.Errorf("不支持的代理选择模式")
	}
	rows, err := client.QueryContext(ctx, query)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()
	var id int64
	if rows.Next() {
		if err = rows.Scan(&id); err != nil {
			return 0, err
		}
	}
	return id, rows.Err()
}

// selectAccountProxyMySQL 是 MySQL 方言实现：random()→RAND()、NOW()→NOW(3)，
// pg_advisory_xact_lock→事务级命名锁（GET_LOCK 随提交/回滚释放）；
// 计数 CTE 在 MySQL 8 原生可用，查询主体保持不变。
func selectAccountProxyMySQL(ctx context.Context, tx *dbent.Tx, mode string) (int64, error) {
	client := tx.Client()
	query := `SELECT p.id FROM proxies p WHERE p.deleted_at IS NULL AND p.status='active' AND (p.expires_at IS NULL OR p.expires_at>NOW(3)) ORDER BY RAND() LIMIT 1`
	switch mode {
	case "random":
	case "least_used":
		if err := txlock.Acquire(ctx, tx, proxyLeastUsedLockNameMySQL); err != nil {
			return 0, err
		}
		query = `WITH bindings AS (
   SELECT a.id AS account_id,a.proxy_id FROM accounts a WHERE a.deleted_at IS NULL AND a.proxy_id IS NOT NULL
  ), counts AS (SELECT proxy_id,COUNT(*) AS n FROM bindings GROUP BY proxy_id)
  SELECT p.id FROM proxies p LEFT JOIN counts c ON c.proxy_id=p.id
  WHERE p.deleted_at IS NULL AND p.status='active' AND (p.expires_at IS NULL OR p.expires_at>NOW(3))
  ORDER BY COALESCE(c.n,0),p.id LIMIT 1`
	default:
		return 0, fmt.Errorf("不支持的代理选择模式")
	}
	rows, err := client.QueryContext(ctx, query)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()
	var id int64
	if rows.Next() {
		if err = rows.Scan(&id); err != nil {
			return 0, err
		}
	}
	return id, rows.Err()
}
