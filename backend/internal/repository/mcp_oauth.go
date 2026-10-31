package repository

import (
	"context"
	"database/sql"
	"errors"
	"sync/atomic"
	"time"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

const mcpOAuthClientIDKeyName = "mcp_oauth_client_id_key"

type mcpOAuthRepository struct {
	client      *dbent.Client
	db          *sql.DB
	clientIDKey atomic.Pointer[[]byte]
}

func NewMCPOAuthRepository(client *dbent.Client, db *sql.DB) service.MCPOAuthRepository {
	return &mcpOAuthRepository{client: client, db: db}
}

// ClientIDKey loads the key that signs stateless client IDs, creating it on
// first use. It is persisted so issued client IDs and grants survive restarts,
// and instances racing to create it converge on the stored value.
func (r *mcpOAuthRepository) ClientIDKey(ctx context.Context) ([]byte, error) {
	if key := r.clientIDKey.Load(); key != nil {
		return *key, nil
	}
	value, _, err := getOrCreateGeneratedSecuritySecret(ctx, r.client, mcpOAuthClientIDKeyName, 32)
	if err != nil {
		return nil, err
	}
	key := []byte(value)
	r.clientIDKey.Store(&key)
	return key, nil
}

func (r *mcpOAuthRepository) CreateAuthorization(ctx context.Context, grant *service.MCPOAuthGrant, code *service.MCPOAuthCode, limit int) error {
	if IsMySQL() {
		return r.createAuthorizationMySQL(ctx, grant, code, limit)
	}
	// Grants are the only rows that outlive a request, so each new one performs
	// bounded retention work. It runs before the owner row is locked, keeping
	// cascaded deletes from blocking other updates to that user. Used refresh
	// hashes remain for the entire grant lifetime so replay detection is never
	// shortened by cleanup.
	if _, err := r.db.ExecContext(ctx, `DELETE FROM mcp_oauth_grants WHERE id IN (SELECT id FROM mcp_oauth_grants WHERE expires_at<$1 ORDER BY expires_at LIMIT 100 FOR UPDATE SKIP LOCKED)`, grant.CreatedAt.Add(-7*24*time.Hour)); err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	// Serialize the per-user limit with other authorizations for this owner.
	var ownerID int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM users WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`, grant.UserID).Scan(&ownerID); err != nil {
		return mcpOAuthSQLError(err)
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM mcp_oauth_grants WHERE user_id=$1 AND revoked_at IS NULL AND expires_at>$2`, grant.UserID, grant.CreatedAt).Scan(&count); err != nil {
		return err
	}
	if count >= limit {
		return service.ErrMCPOAuthGrantLimit
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mcp_oauth_grants (id,client_id,client_name,user_id,token_version,resource,scope,read_only,created_at,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		grant.ID, grant.ClientID, grant.ClientName, grant.UserID, grant.TokenVersion, grant.Resource, grant.Scope, grant.ReadOnly, grant.CreatedAt, grant.ExpiresAt)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mcp_oauth_codes (code_hash,grant_id,client_id,redirect_uri,resource,code_challenge,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		code.Hash, code.GrantID, code.ClientID, code.RedirectURI, code.Resource, code.CodeChallenge, code.ExpiresAt)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (r *mcpOAuthRepository) GetCode(ctx context.Context, hash string) (*service.MCPOAuthCode, error) {
	if IsMySQL() {
		return r.getCodeMySQL(ctx, hash)
	}
	code := &service.MCPOAuthCode{}
	err := r.db.QueryRowContext(ctx, `SELECT code_hash,grant_id,client_id,redirect_uri,resource,code_challenge,expires_at,consumed_at FROM mcp_oauth_codes WHERE code_hash=$1`, hash).
		Scan(&code.Hash, &code.GrantID, &code.ClientID, &code.RedirectURI, &code.Resource, &code.CodeChallenge, &code.ExpiresAt, &code.ConsumedAt)
	if err != nil {
		return nil, mcpOAuthSQLError(err)
	}
	return code, nil
}

func (r *mcpOAuthRepository) GetCredential(ctx context.Context, hash string) (*service.MCPOAuthCredential, error) {
	if IsMySQL() {
		return r.getCredentialMySQL(ctx, hash)
	}
	credential := &service.MCPOAuthCredential{}
	err := r.db.QueryRowContext(ctx, `SELECT key_hash,grant_id,kind,expires_at,used_at FROM mcp_oauth_credentials WHERE key_hash=$1`, hash).
		Scan(&credential.Hash, &credential.GrantID, &credential.Kind, &credential.ExpiresAt, &credential.UsedAt)
	if err != nil {
		return nil, mcpOAuthSQLError(err)
	}
	return credential, nil
}

const mcpOAuthGrantColumns = `id,client_id,client_name,user_id,token_version,resource,scope,read_only,created_at,expires_at,last_used_at,revoked_at`

func scanMCPOAuthGrant(row interface{ Scan(...any) error }) (*service.MCPOAuthGrant, error) {
	grant := &service.MCPOAuthGrant{}
	err := row.Scan(&grant.ID, &grant.ClientID, &grant.ClientName, &grant.UserID, &grant.TokenVersion, &grant.Resource, &grant.Scope, &grant.ReadOnly, &grant.CreatedAt, &grant.ExpiresAt, &grant.LastUsedAt, &grant.RevokedAt)
	if err != nil {
		return nil, mcpOAuthSQLError(err)
	}
	return grant, nil
}

func (r *mcpOAuthRepository) GetGrant(ctx context.Context, id string) (*service.MCPOAuthGrant, error) {
	if IsMySQL() {
		return scanMCPOAuthGrant(r.db.QueryRowContext(ctx, `SELECT `+mcpOAuthGrantColumns+` FROM mcp_oauth_grants WHERE id=?`, id))
	}
	return scanMCPOAuthGrant(r.db.QueryRowContext(ctx, `SELECT `+mcpOAuthGrantColumns+` FROM mcp_oauth_grants WHERE id=$1`, id))
}

func (r *mcpOAuthRepository) ListGrants(ctx context.Context, userID int64) ([]*service.MCPOAuthGrant, error) {
	query := `SELECT ` + mcpOAuthGrantColumns + ` FROM mcp_oauth_grants WHERE user_id=$1 ORDER BY created_at DESC`
	if IsMySQL() {
		query = `SELECT ` + mcpOAuthGrantColumns + ` FROM mcp_oauth_grants WHERE user_id=? ORDER BY created_at DESC`
	}
	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	grants := []*service.MCPOAuthGrant{}
	for rows.Next() {
		grant, err := scanMCPOAuthGrant(rows)
		if err != nil {
			return nil, err
		}
		grants = append(grants, grant)
	}
	return grants, rows.Err()
}

func (r *mcpOAuthRepository) ExchangeCode(ctx context.Context, hash, grantID string, at time.Time, access, refresh *service.MCPOAuthCredential) error {
	return r.consumeAndIssue(ctx, hash, grantID, at, access, refresh, false)
}

func (r *mcpOAuthRepository) RotateRefresh(ctx context.Context, hash, grantID string, at time.Time, access, refresh *service.MCPOAuthCredential) error {
	return r.consumeAndIssue(ctx, hash, grantID, at, access, refresh, true)
}

func (r *mcpOAuthRepository) consumeAndIssue(ctx context.Context, hash, grantID string, at time.Time, access, refresh *service.MCPOAuthCredential, rotating bool) error {
	if IsMySQL() {
		return r.consumeAndIssueMySQL(ctx, hash, grantID, at, access, refresh, rotating)
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	// Always lock the grant first: rotation, code exchange, and revocation
	// serialize on the same family without code/refresh lock-order inversion.
	var revokedAt *time.Time
	var grantExpiry time.Time
	if err := tx.QueryRowContext(ctx, `SELECT revoked_at,expires_at FROM mcp_oauth_grants WHERE id=$1 FOR UPDATE`, grantID).Scan(&revokedAt, &grantExpiry); err != nil {
		return mcpOAuthSQLError(err)
	}
	if revokedAt != nil || !at.Before(grantExpiry) {
		return service.ErrMCPOAuthNotFound
	}
	var expiresAt time.Time
	var usedAt *time.Time
	query := `SELECT expires_at,consumed_at FROM mcp_oauth_codes WHERE code_hash=$1 AND grant_id=$2 FOR UPDATE`
	if rotating {
		query = `SELECT expires_at,used_at FROM mcp_oauth_credentials WHERE key_hash=$1 AND grant_id=$2 AND kind='refresh' FOR UPDATE`
	}
	if err := tx.QueryRowContext(ctx, query, hash, grantID).Scan(&expiresAt, &usedAt); err != nil {
		return mcpOAuthSQLError(err)
	}
	if usedAt != nil {
		// Do not return before committing: rolling back here would leave all
		// newer credentials usable after a detected replay.
		if _, err := tx.ExecContext(ctx, `UPDATE mcp_oauth_grants SET revoked_at=$2 WHERE id=$1`, grantID, at); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		return service.ErrMCPOAuthNotFound
	}
	if !at.Before(expiresAt) {
		return service.ErrMCPOAuthNotFound
	}
	query = `UPDATE mcp_oauth_codes SET consumed_at=$2 WHERE code_hash=$1`
	if rotating {
		query = `UPDATE mcp_oauth_credentials SET used_at=$2 WHERE key_hash=$1`
	}
	if _, err := tx.ExecContext(ctx, query, hash, at); err != nil {
		return err
	}
	for _, credential := range []*service.MCPOAuthCredential{access, refresh} {
		if credential == nil {
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO mcp_oauth_credentials (key_hash,grant_id,kind,expires_at) VALUES ($1,$2,$3,$4)`, credential.Hash, grantID, credential.Kind, credential.ExpiresAt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r *mcpOAuthRepository) TouchGrant(ctx context.Context, id string, at time.Time) error {
	if IsMySQL() {
		return r.touchGrantMySQL(ctx, id, at)
	}
	return mcpOAuthResult(r.db.ExecContext(ctx, `UPDATE mcp_oauth_grants SET last_used_at=$2 WHERE id=$1 AND revoked_at IS NULL AND expires_at>$2`, id, at))
}

func (r *mcpOAuthRepository) RevokeGrant(ctx context.Context, userID int64, id string, at time.Time) error {
	if IsMySQL() {
		return r.revokeGrantMySQL(ctx, userID, id, at)
	}
	return mcpOAuthResult(r.db.ExecContext(ctx, `UPDATE mcp_oauth_grants SET revoked_at=COALESCE(revoked_at,$3) WHERE id=$1 AND user_id=$2`, id, userID, at))
}

func (r *mcpOAuthRepository) RevokeUserGrants(ctx context.Context, userID int64, at time.Time) error {
	return revokeMCPGrants(ctx, r.db, userID, false, at)
}

// revokeMCPGrants persists revocation instead of relying on per-request user
// checks, so restoring an account or role cannot revive earlier grants.
func revokeMCPGrants(ctx context.Context, exec sqlExecutor, userID int64, adminOnly bool, at time.Time) error {
	query := `UPDATE mcp_oauth_grants SET revoked_at=$2 WHERE user_id=$1 AND revoked_at IS NULL`
	// PG 按 $n 编号绑定，MySQL 按 ? 的书写顺序绑定：SET 子句在前，
	// 因此 MySQL 分支的参数顺序是 (at, userID)。
	args := []any{userID, at}
	if IsMySQL() {
		query = `UPDATE mcp_oauth_grants SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL`
		args = []any{at, userID}
	}
	if adminOnly {
		query += ` AND scope='admin'`
	}
	_, err := exec.ExecContext(ctx, query, args...)
	return err
}

func mcpOAuthSQLError(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return service.ErrMCPOAuthNotFound
	}
	return err
}

func mcpOAuthResult(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return service.ErrMCPOAuthNotFound
	}
	return nil
}

// ---- MySQL 方言实现 ----
//
// 与上面的 PostgreSQL 版本一一对应，SQL 语义保持一致，差异只有两类：
//   - 占位符：MySQL 分支用 ?（ent 不替原生 SQL 改写占位符）；
//   - MySQL 限制：DELETE 的子查询不能直接读同一张目标表（错误 1093，需套派生表）；
//     RowsAffected 只统计真正被修改的行，目标值等于旧值时为 0，
//     需要按同一谓词回查补齐 PG 的「匹配行数」语义。

func (r *mcpOAuthRepository) createAuthorizationMySQL(ctx context.Context, grant *service.MCPOAuthGrant, code *service.MCPOAuthCode, limit int) error {
	// 与 PG 版相同的保留策略；LIMIT 必须写在 FOR UPDATE 之前（8.0 语法要求），
	// 外层再包一层派生表绕开 1093。
	if _, err := r.db.ExecContext(ctx, `DELETE FROM mcp_oauth_grants WHERE id IN (SELECT id FROM (SELECT id FROM mcp_oauth_grants WHERE expires_at<? ORDER BY expires_at LIMIT 100 FOR UPDATE SKIP LOCKED) AS expired_grants)`, grant.CreatedAt.Add(-7*24*time.Hour)); err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var ownerID int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM users WHERE id=? AND deleted_at IS NULL FOR UPDATE`, grant.UserID).Scan(&ownerID); err != nil {
		return mcpOAuthSQLError(err)
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM mcp_oauth_grants WHERE user_id=? AND revoked_at IS NULL AND expires_at>?`, grant.UserID, grant.CreatedAt).Scan(&count); err != nil {
		return err
	}
	if count >= limit {
		return service.ErrMCPOAuthGrantLimit
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mcp_oauth_grants (id,client_id,client_name,user_id,token_version,resource,scope,read_only,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?)`,
		grant.ID, grant.ClientID, grant.ClientName, grant.UserID, grant.TokenVersion, grant.Resource, grant.Scope, grant.ReadOnly, grant.CreatedAt, grant.ExpiresAt)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO mcp_oauth_codes (code_hash,grant_id,client_id,redirect_uri,resource,code_challenge,expires_at) VALUES (?,?,?,?,?,?,?)`,
		code.Hash, code.GrantID, code.ClientID, code.RedirectURI, code.Resource, code.CodeChallenge, code.ExpiresAt)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (r *mcpOAuthRepository) getCodeMySQL(ctx context.Context, hash string) (*service.MCPOAuthCode, error) {
	code := &service.MCPOAuthCode{}
	err := r.db.QueryRowContext(ctx, `SELECT code_hash,grant_id,client_id,redirect_uri,resource,code_challenge,expires_at,consumed_at FROM mcp_oauth_codes WHERE code_hash=?`, hash).
		Scan(&code.Hash, &code.GrantID, &code.ClientID, &code.RedirectURI, &code.Resource, &code.CodeChallenge, &code.ExpiresAt, &code.ConsumedAt)
	if err != nil {
		return nil, mcpOAuthSQLError(err)
	}
	return code, nil
}

func (r *mcpOAuthRepository) getCredentialMySQL(ctx context.Context, hash string) (*service.MCPOAuthCredential, error) {
	credential := &service.MCPOAuthCredential{}
	err := r.db.QueryRowContext(ctx, `SELECT key_hash,grant_id,kind,expires_at,used_at FROM mcp_oauth_credentials WHERE key_hash=?`, hash).
		Scan(&credential.Hash, &credential.GrantID, &credential.Kind, &credential.ExpiresAt, &credential.UsedAt)
	if err != nil {
		return nil, mcpOAuthSQLError(err)
	}
	return credential, nil
}

func (r *mcpOAuthRepository) consumeAndIssueMySQL(ctx context.Context, hash, grantID string, at time.Time, access, refresh *service.MCPOAuthCredential, rotating bool) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var revokedAt *time.Time
	var grantExpiry time.Time
	if err := tx.QueryRowContext(ctx, `SELECT revoked_at,expires_at FROM mcp_oauth_grants WHERE id=? FOR UPDATE`, grantID).Scan(&revokedAt, &grantExpiry); err != nil {
		return mcpOAuthSQLError(err)
	}
	if revokedAt != nil || !at.Before(grantExpiry) {
		return service.ErrMCPOAuthNotFound
	}
	var expiresAt time.Time
	var usedAt *time.Time
	query := `SELECT expires_at,consumed_at FROM mcp_oauth_codes WHERE code_hash=? AND grant_id=? FOR UPDATE`
	if rotating {
		query = `SELECT expires_at,used_at FROM mcp_oauth_credentials WHERE key_hash=? AND grant_id=? AND kind='refresh' FOR UPDATE`
	}
	if err := tx.QueryRowContext(ctx, query, hash, grantID).Scan(&expiresAt, &usedAt); err != nil {
		return mcpOAuthSQLError(err)
	}
	if usedAt != nil {
		// 与 PG 版一致：检测到重放时先吊销整个家族并提交，而不是回滚。
		if _, err := tx.ExecContext(ctx, `UPDATE mcp_oauth_grants SET revoked_at=? WHERE id=?`, at, grantID); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		return service.ErrMCPOAuthNotFound
	}
	if !at.Before(expiresAt) {
		return service.ErrMCPOAuthNotFound
	}
	query = `UPDATE mcp_oauth_codes SET consumed_at=? WHERE code_hash=?`
	if rotating {
		query = `UPDATE mcp_oauth_credentials SET used_at=? WHERE key_hash=?`
	}
	if _, err := tx.ExecContext(ctx, query, at, hash); err != nil {
		return err
	}
	for _, credential := range []*service.MCPOAuthCredential{access, refresh} {
		if credential == nil {
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO mcp_oauth_credentials (key_hash,grant_id,kind,expires_at) VALUES (?,?,?,?)`, credential.Hash, grantID, credential.Kind, credential.ExpiresAt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r *mcpOAuthRepository) touchGrantMySQL(ctx context.Context, id string, at time.Time) error {
	result, err := r.db.ExecContext(ctx, `UPDATE mcp_oauth_grants SET last_used_at=? WHERE id=? AND revoked_at IS NULL AND expires_at>?`, at, id, at)
	if err != nil {
		return err
	}
	return mcpOAuthResultMySQL(ctx, r.db, result, `SELECT 1 FROM mcp_oauth_grants WHERE id=? AND revoked_at IS NULL AND expires_at>?`, id, at)
}

func (r *mcpOAuthRepository) revokeGrantMySQL(ctx context.Context, userID int64, id string, at time.Time) error {
	result, err := r.db.ExecContext(ctx, `UPDATE mcp_oauth_grants SET revoked_at=COALESCE(revoked_at,?) WHERE id=? AND user_id=?`, at, id, userID)
	if err != nil {
		return err
	}
	return mcpOAuthResultMySQL(ctx, r.db, result, `SELECT 1 FROM mcp_oauth_grants WHERE id=? AND user_id=?`, id, userID)
}

// mcpOAuthResultMySQL 按 PG 的 RowsAffected 语义判定：MySQL 只统计被修改的行，
// 幂等更新（如重复撤销）返回 0 但谓词实际匹配到了行，此时回查一次避免误报 NotFound。
func mcpOAuthResultMySQL(ctx context.Context, db *sql.DB, result sql.Result, matchQuery string, args ...any) error {
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	var one int
	if err := db.QueryRowContext(ctx, matchQuery, args...).Scan(&one); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return service.ErrMCPOAuthNotFound
		}
		return err
	}
	return nil
}
