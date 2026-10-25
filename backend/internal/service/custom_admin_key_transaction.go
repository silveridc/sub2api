package service

import (
	"context"
	"fmt"

	"entgo.io/ent/dialect"
	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/util/txlock"
)

// scopedAdminAccountLockNameMySQL 是 MySQL 方言下受限账户写事务的命名锁前缀，
// 与 PG 侧 hashtextextended('scoped_admin_account:'||id) 一一对应（锁名上限 64 字符）。
const scopedAdminAccountLockNameMySQL = "sub2api:scoped_admin_account:"

func lockScopedAdminAccount(ctx context.Context, tx *dbent.Tx, id int64) error {
	// 方言门：PG 用事务级咨询锁（随事务自动释放、无限等待）；
	// MySQL 用 GET_LOCK 命名锁，由 ent 提交/回滚钩子在事务结束前释放，等待有界。
	if tx.Client().Driver().Dialect() == dialect.MySQL {
		return txlock.Acquire(ctx, tx, scopedAdminAccountLockNameMySQL+fmt.Sprint(id))
	}
	_, err := tx.Client().ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('scoped_admin_account:' || $1::text, 0))`, id)
	return err
}

// AfterAccountCommit 将不参与回滚的缓存和上游副作用延迟到事务提交成功后。
// 普通管理员没有外层事务时立即执行，保留原有行为。
func AfterAccountCommit(ctx context.Context, run func(context.Context)) {
	if tx := dbent.TxFromContext(ctx); tx != nil {
		tx.OnCommit(func(next dbent.Committer) dbent.Committer {
			return dbent.CommitFunc(func(commitCtx context.Context, tx *dbent.Tx) error {
				if err := next.Commit(commitCtx, tx); err != nil {
					return err
				}
				run(dbent.NewTxContext(ctx, nil))
				return nil
			})
		})
	} else {
		run(ctx)
	}
}
