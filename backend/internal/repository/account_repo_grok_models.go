package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

var errGrokCatalogInvalidJSON = errors.New("grok model catalog: invalid json")

var _ service.GrokCatalogSnapshotRepository = (*accountRepository)(nil)

const compareAndSwapGrokObservedModelsSQL = `UPDATE accounts
SET extra = jsonb_set(COALESCE(extra, '{}'::jsonb), '{grok_observed_models}', $3::jsonb, true),
    updated_at = NOW()
WHERE id = $1 AND deleted_at IS NULL AND platform = 'grok'
  AND COALESCE(extra -> 'grok_observed_models', 'null'::jsonb) = $2::jsonb`

// MySQL 版：jsonb_set/-> 无法直接翻译，用 JSON_SET + JSON_EXTRACT；
// 两侧都经 CAST(… AS JSON) 归一化后按文本比较，避免不同 8.0 小版本的
// JSON 比较语义差异。占位符按语句出现顺序重排为 (next, id, expected)。
const compareAndSwapGrokObservedModelsMySQL = `UPDATE accounts
SET extra = JSON_SET(COALESCE(extra, JSON_OBJECT()), '$.grok_observed_models', CAST(? AS JSON)),
    updated_at = NOW(3)
WHERE id = ? AND deleted_at IS NULL AND platform = 'grok'
  AND COALESCE(CAST(JSON_EXTRACT(extra, '$.grok_observed_models') AS CHAR), 'null') = CAST(CAST(? AS JSON) AS CHAR)`

func (r *accountRepository) CompareAndSwapGrokObservedModels(ctx context.Context, id int64, expected, next json.RawMessage) (bool, error) {
	if scoped := r.accountTransactionScope(ctx); scoped != r {
		return scoped.CompareAndSwapGrokObservedModels(ctx, id, expected, next)
	}
	expectedArg, err := grokCatalogJSONArg(expected)
	if err != nil {
		return false, err
	}
	nextArg, err := grokCatalogJSONArg(next)
	if err != nil {
		return false, err
	}
	query := compareAndSwapGrokObservedModelsSQL
	args := []any{id, expectedArg, nextArg}
	if IsMySQL() {
		query = compareAndSwapGrokObservedModelsMySQL
		args = []any{nextArg, id, expectedArg}
	}
	result, err := clientFromContext(ctx, r.client).ExecContext(ctx, query, args...)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if affected == 0 {
		return false, nil
	}
	if dbent.TxFromContext(ctx) == nil {
		r.syncSchedulerAccountSnapshot(ctx, id)
	}
	return true, nil
}

func grokCatalogJSONArg(raw json.RawMessage) (string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return "null", nil
	}
	if !json.Valid(trimmed) {
		return "", errGrokCatalogInvalidJSON
	}
	return string(trimmed), nil
}
