//go:build integration

package repository

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	dbaccount "github.com/Wei-Shaw/sub2api/ent/account"
	"github.com/Wei-Shaw/sub2api/internal/pkg/adminaccess"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

// TestScopedAdminKeyRoundTripAndNoOpWrites 在真实 schema 上跑通受限管理密钥的读写闭环，
// 并钉住 MySQL 方言的两个易错点：JSON 列往返（PG 用 JSONB）、
// RowsAffected 只计「值发生变化」的行（DSN 未开 clientFoundRows，同值重放会得到 0）。
func TestScopedAdminKeyRoundTripAndNoOpWrites(t *testing.T) {
	ctx := context.Background()
	client := integrationEntClient
	owner := mustCreateUser(t, client, &service.User{})
	t.Cleanup(func() {
		_, _ = integrationDB.ExecContext(context.Background(), "DELETE FROM scoped_admin_api_keys WHERE created_by = "+ph(1), owner.ID)
		_ = client.User.DeleteOneID(owner.ID).Exec(context.Background())
	})

	repo := NewScopedAdminKeyRepository(integrationDB)
	now := time.Now().Truncate(dbTimePrecision())
	expires := now.Add(24 * time.Hour)
	id := "sk" + strconv.FormatInt(now.UnixNano(), 36)
	key := &service.ScopedAdminKey{
		ScopedAdminKeyInput: service.ScopedAdminKeyInput{
			Name:       "往返验证",
			Enabled:    true,
			ExpiresAt:  &expires,
			AllowedIPs: []string{"10.0.0.0/8", "192.0.2.0/24"},
			Policy: adminaccess.Policy{Rules: []adminaccess.Rule{{
				Permissions:  []string{"accounts.read"},
				AccountTypes: []string{"oauth"},
			}}},
		},
		ID: id, KeyPrefix: "sub2api_ab", Hash: strings.Repeat("a", 64),
		CreatedBy: owner.ID, CreatedAt: now, UpdatedAt: now,
	}
	require.NoError(t, repo.InsertScopedAdminKey(ctx, key))
	t.Cleanup(func() {
		_, _ = integrationDB.ExecContext(context.Background(), "DELETE FROM scoped_admin_api_keys WHERE id = "+ph(1), id)
	})

	stored, err := repo.GetScopedAdminKey(ctx, id)
	require.NoError(t, err)
	require.True(t, stored.Enabled)
	require.Equal(t, key.AllowedIPs, stored.AllowedIPs)
	require.Len(t, stored.Policy.Rules, 1)
	require.Equal(t, []string{"accounts.read"}, stored.Policy.Rules[0].Permissions)
	require.NotNil(t, stored.ExpiresAt)
	require.True(t, stored.ExpiresAt.Equal(expires))
	require.Empty(t, stored.LastUsedIP)

	items, err := repo.ListScopedAdminKeys(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, items)

	// 同值重放：编辑弹窗未改动任何字段直接提交，不能被判成「密钥不存在」。
	require.NoError(t, repo.UpdateScopedAdminKey(ctx, stored))
	// 同一毫秒内的重复 Touch（last_used_at / last_used_ip 完全相同）同样必须成功。
	require.NoError(t, repo.TouchScopedAdminKey(ctx, id, stored.Hash, stored.UpdatedAt, "10.0.0.1", stored.UpdatedAt))
	require.NoError(t, repo.TouchScopedAdminKey(ctx, id, stored.Hash, stored.UpdatedAt, "10.0.0.1", stored.UpdatedAt))

	used, err := repo.GetScopedAdminKey(ctx, id)
	require.NoError(t, err)
	require.Equal(t, "10.0.0.1", used.LastUsedIP)

	// CAS 失败仍要如实报错：过期的 updated_at 不得 Touch 成功。
	require.Error(t, repo.TouchScopedAdminKey(ctx, id, used.Hash, now.Add(-time.Hour), "10.0.0.2", now))

	require.NoError(t, repo.RotateScopedAdminKeyHash(ctx, id, used.Hash, strings.Repeat("b", 64), time.Now().Truncate(dbTimePrecision())))
	require.ErrorIs(t, repo.RotateScopedAdminKeyHash(ctx, id, used.Hash, strings.Repeat("c", 64), time.Now().Truncate(dbTimePrecision())), service.ErrScopedAdminKeyConflict)

	// 未撤销的密钥不能删除记录；撤销后删除只隐藏列表项，底层记录保留。
	require.ErrorIs(t, repo.DeleteScopedAdminKeyRecord(ctx, id, time.Now().Truncate(dbTimePrecision())), service.ErrScopedAdminKeyNotFound)
	require.NoError(t, repo.RevokeScopedAdminKey(ctx, id, time.Now().Truncate(dbTimePrecision())))
	require.ErrorIs(t, repo.RevokeScopedAdminKey(ctx, id, time.Now().Truncate(dbTimePrecision())), service.ErrScopedAdminKeyNotFound)
	require.NoError(t, repo.DeleteScopedAdminKeyRecord(ctx, id, time.Now().Truncate(dbTimePrecision())))
	hidden, err := repo.GetScopedAdminKey(ctx, id)
	require.NoError(t, err)
	require.NotNil(t, hidden.RevokedAt)
}

// TestScopedCodexIdentityPredicatesMatchStoredCredentials 双方言跑通受限密钥导入候选的身份匹配，
// 覆盖 MySQL 侧需要手工复刻的构造：JSON 文本取值、数值归一化、按 Unicode 空白集合裁剪首尾。
func TestScopedCodexIdentityPredicatesMatchStoredCredentials(t *testing.T) {
	ctx := context.Background()
	client := integrationEntClient

	padded := mustCreateAccount(t, client, &service.Account{
		Name: "codex-identity-padded", Platform: service.PlatformOpenAI, Type: service.AccountTypeOAuth,
		Credentials: map[string]any{"chatgpt_account_id": "\tworkspace　", "chatgpt_user_id": "member"},
	})
	numeric := mustCreateAccount(t, client, &service.Account{
		Name: "codex-identity-numeric", Platform: service.PlatformOpenAI, Type: service.AccountTypeOAuth,
		// 旧数据里的数字形式标识：文档写 1e7，匹配前两侧都要展开成 10000000。
		Credentials: map[string]any{"chatgpt_user_id": json.RawMessage("1e7")},
	})
	emailOnly := mustCreateAccount(t, client, &service.Account{
		Name: "codex-identity-email", Platform: service.PlatformOpenAI, Type: service.AccountTypeOAuth,
		Credentials: map[string]any{"email": "\tUser@Example.COM "},
	})
	other := mustCreateAccount(t, client, &service.Account{
		Name: "codex-identity-other", Platform: service.PlatformOpenAI, Type: service.AccountTypeOAuth,
		Credentials: map[string]any{"chatgpt_account_id": "workspace", "chatgpt_user_id": "someone-else"},
	})
	ids := []int64{padded.ID, numeric.ID, emailOnly.ID, other.ID}
	t.Cleanup(func() {
		for _, id := range ids {
			_ = client.Account.DeleteOneID(id).Exec(context.Background())
		}
	})

	matchedIDs := func(identity service.ScopedCodexIdentity) []int64 {
		t.Helper()
		predicates := scopedCodexIdentityPredicates(identity)
		require.NotEmpty(t, predicates)
		rows, err := client.Account.Query().Where(predicates[0], dbaccount.IDIn(ids...)).Order(dbent.Asc(dbaccount.FieldID)).All(ctx)
		require.NoError(t, err)
		got := make([]int64, 0, len(rows))
		for _, row := range rows {
			got = append(got, row.ID)
		}
		return got
	}

	// 首尾空白（含全角空格）在数据库侧裁掉后才能命中。
	require.Equal(t, []int64{padded.ID}, matchedIDs(service.ScopedCodexIdentity{AccountID: "workspace", UserID: "member"}))
	// 数字形式标识按 float64 语义展开指数。
	require.Equal(t, []int64{numeric.ID}, matchedIDs(service.ScopedCodexIdentity{UserID: "10000000"}))
	// 邮箱匹配走小写归一。
	require.Equal(t, []int64{emailOnly.ID}, matchedIDs(service.ScopedCodexIdentity{Email: "user@example.com"}))
	// 仅给出账户 ID 时走「账户标识精确命中」分支：首尾空白已在两侧裁掉，
	// 带空白的 padded 与正常写法的 other 都应命中。
	require.Equal(t, []int64{padded.ID, other.ID}, matchedIDs(service.ScopedCodexIdentity{AccountID: "workspace"}))
}

// TestSelectAccountProxyModes 双方言验证自动代理选择：随机模式、最空闲模式（含事务级命名锁）
// 与过期代理的排除。
func TestSelectAccountProxyModes(t *testing.T) {
	ctx := context.Background()
	client := integrationEntClient

	busy := mustCreateProxy(t, client, &service.Proxy{Name: "scoped-proxy-busy"})
	idleA := mustCreateProxy(t, client, &service.Proxy{Name: "scoped-proxy-idle-a"})
	idleB := mustCreateProxy(t, client, &service.Proxy{Name: "scoped-proxy-idle-b"})
	expired := mustCreateProxy(t, client, &service.Proxy{Name: "scoped-proxy-expired"})
	_, err := client.Proxy.UpdateOneID(expired.ID).SetExpiresAt(time.Now().Add(-time.Hour)).Save(ctx)
	require.NoError(t, err)
	proxyIDs := []int64{busy.ID, idleA.ID, idleB.ID, expired.ID}
	t.Cleanup(func() {
		for _, id := range proxyIDs {
			_ = client.Proxy.DeleteOneID(id).Exec(context.Background())
		}
	})

	bound := mustCreateAccount(t, client, &service.Account{
		Name: "scoped-proxy-bound", Platform: service.PlatformOpenAI, Type: service.AccountTypeOAuth, ProxyID: &busy.ID,
	})
	t.Cleanup(func() { _ = client.Account.DeleteOneID(bound.ID).Exec(context.Background()) })

	repo := &proxyRepository{client: client}

	tx, err := client.Tx(ctx)
	require.NoError(t, err)
	txctx := dbent.NewTxContext(ctx, tx)
	// 同一事务内取两次最空闲代理：命名锁可重入，提交时按取锁次数成对释放。
	first, err := repo.SelectAccountProxy(txctx, "least_used")
	require.NoError(t, err)
	require.NotEqual(t, busy.ID, first, "已绑定的代理不应再被判为最空闲")
	require.NotEqual(t, expired.ID, first, "过期代理不参与选择")
	second, err := repo.SelectAccountProxy(txctx, "least_used")
	require.NoError(t, err)
	require.NotEqual(t, expired.ID, second)
	random, err := repo.SelectAccountProxy(txctx, "random")
	require.NoError(t, err)
	require.Positive(t, random)
	require.NotEqual(t, expired.ID, random)
	_, err = repo.SelectAccountProxy(txctx, "specified")
	require.Error(t, err)
	require.NoError(t, tx.Commit())

	// 提交后锁必须已释放，否则后续事务会被自己进程内残留的连接级锁拖到超时。
	otherTx, err := client.Tx(ctx)
	require.NoError(t, err)
	picked, err := repo.SelectAccountProxy(dbent.NewTxContext(ctx, otherTx), "least_used")
	require.NoError(t, err)
	require.Positive(t, picked)
	require.NoError(t, otherTx.Rollback())
}
