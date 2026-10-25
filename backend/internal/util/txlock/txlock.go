// Package txlock 提供事务级命名锁，用于 MySQL 方言下替代 pg_advisory_xact_lock。
//
// MySQL 的 GET_LOCK 是连接级且不会随事务结束自动释放，而 ent 事务固定占用一条连接，
// 因此这里在取锁后挂载 ent 的 OnCommit / OnRollback 钩子，在事务真正结束之前用同一连接释放。
package txlock

import (
	"context"
	"database/sql"
	"fmt"
	"sync"

	dbent "github.com/Wei-Shaw/sub2api/ent"
)

// waitTimeoutSeconds 是获取命名锁的最长等待时间。
// PG 的咨询锁会无限等待，这里改为有界等待，避免持锁连接异常残留时把请求挂死。
const waitTimeoutSeconds = 30

// Acquire 在 MySQL 方言下取事务级命名锁，锁随事务提交或回滚释放。
// 调用方必须保证 tx 与其后续写操作在同一事务内。
func Acquire(ctx context.Context, tx *dbent.Tx, name string) error {
	var acquired int
	rows, err := tx.Client().QueryContext(ctx, "SELECT GET_LOCK(?, ?)", name, waitTimeoutSeconds)
	if err != nil {
		return fmt.Errorf("acquire mysql named lock %q: %w", name, err)
	}
	if rows.Next() {
		err = rows.Scan(&acquired)
	} else {
		err = sql.ErrNoRows
	}
	_ = rows.Close()
	if err != nil {
		return fmt.Errorf("acquire mysql named lock %q: %w", name, err)
	}
	if acquired != 1 {
		return fmt.Errorf("mysql named lock %q wait timed out after %ds", name, waitTimeoutSeconds)
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			// 释放失败（如连接已断）不阻断提交：锁随连接关闭而消失，最多让其他会话等到超时。
			_, _ = tx.Client().ExecContext(context.WithoutCancel(ctx), "SELECT RELEASE_LOCK(?)", name)
		})
	}
	tx.OnCommit(func(next dbent.Committer) dbent.Committer {
		return dbent.CommitFunc(func(commitCtx context.Context, commitTx *dbent.Tx) error {
			release()
			return next.Commit(commitCtx, commitTx)
		})
	})
	tx.OnRollback(func(next dbent.Rollbacker) dbent.Rollbacker {
		return dbent.RollbackFunc(func(rollbackCtx context.Context, rollbackTx *dbent.Tx) error {
			release()
			return next.Rollback(rollbackCtx, rollbackTx)
		})
	})
	return nil
}
