package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	entsql "entgo.io/ent/dialect/sql"
	dbent "github.com/Wei-Shaw/sub2api/ent"
	dbaccount "github.com/Wei-Shaw/sub2api/ent/account"
	dbaccountgroup "github.com/Wei-Shaw/sub2api/ent/accountgroup"
	dbpredicate "github.com/Wei-Shaw/sub2api/ent/predicate"
	"github.com/Wei-Shaw/sub2api/internal/pkg/adminaccess"
	"github.com/Wei-Shaw/sub2api/internal/pkg/pagination"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

func (r *accountRepository) ScopedAdminList(ctx context.Context, p pagination.PaginationParams, platform, kind, status, search string) ([]service.Account, int64, error) {
	principal := adminaccess.FromContext(ctx)
	if principal == nil {
		return nil, 0, fmt.Errorf("缺少受限身份")
	}
	alternatives := scopedAdminAccountPredicates(principal.Policy, "accounts.read")
	if len(alternatives) == 0 {
		return []service.Account{}, 0, nil
	}
	q := r.accountListFilteredQuery(platform, kind, status, search, 0, "").Where(dbaccount.Or(alternatives...))
	total, err := q.Clone().Count(ctx)
	if err != nil {
		return nil, 0, err
	}
	// SQL 只投影模型映射子字段，不加载 Token、API Key、接入地址或其他凭证。
	var rows []struct {
		ID           int64
		Name         string
		Notes        *string
		Platform     string
		Type         string
		Status       string
		Schedulable  bool
		Concurrency  int
		Priority     int
		ModelMapping json.RawMessage `json:"model_mapping"`
	}
	err = q.Offset(p.Offset()).Limit(p.Limit()).Order(dbaccount.ByID()).
		Select(dbaccount.FieldID, dbaccount.FieldName, dbaccount.FieldNotes, dbaccount.FieldPlatform, dbaccount.FieldType, dbaccount.FieldStatus, dbaccount.FieldSchedulable, dbaccount.FieldConcurrency, dbaccount.FieldPriority).
		Aggregate(func(s *entsql.Selector) string {
			if IsMySQL() {
				return "JSON_EXTRACT(" + s.C(dbaccount.FieldCredentials) + ", '$.model_mapping') AS model_mapping"
			}
			return s.C(dbaccount.FieldCredentials) + "->'model_mapping' AS model_mapping"
		}).Scan(ctx, &rows)
	if err != nil {
		return nil, 0, err
	}
	accounts := make([]service.Account, 0, len(rows))
	for _, row := range rows {
		groups, e := r.loadAccountGroupIDs(ctx, row.ID)
		if e != nil {
			return nil, 0, e
		}
		var rawMapping map[string]any
		mapping := map[string]string{}
		if json.Unmarshal(row.ModelMapping, &rawMapping) == nil {
			for source, target := range rawMapping {
				if value, ok := target.(string); ok {
					mapping[source] = value
				}
			}
		}
		var credentials map[string]any
		if len(mapping) > 0 {
			credentials = map[string]any{"model_mapping": mapping}
		}
		accounts = append(accounts, service.Account{ID: row.ID, Name: row.Name, Notes: row.Notes, Platform: row.Platform, Type: row.Type, Status: row.Status, Schedulable: row.Schedulable, Concurrency: row.Concurrency, Priority: row.Priority, GroupIDs: groups, Credentials: credentials})
	}
	return accounts, int64(total), nil
}

// ScopedAdminCommitted 提交后按实际操作删除或更新缓存，避免对已删除账户读取快照。
func (r *accountRepository) ScopedAdminCommitted(ctx context.Context, id int64, deleted bool) {
	if deleted {
		r.deleteSchedulerAccountSnapshot(ctx, id)
		return
	}
	r.syncSchedulerAccountSnapshot(ctx, id)
}

// scopedAdminBindGroups 只增删变化的关联，保留现有关联的优先级和创建时间。
// 调用者已在受限事务内验权并合并不可操作的分组，不得回退到全量重建。
func (r *accountRepository) scopedAdminBindGroups(ctx context.Context, accountID int64, groupIDs []int64) error {
	if dbent.TxFromContext(ctx) == nil {
		return fmt.Errorf("受限分组写入需要数据库事务")
	}
	existing, err := r.loadAccountGroupIDs(ctx, accountID)
	if err != nil {
		return err
	}
	added, removed := []int64{}, []int64{}
	for _, id := range groupIDs {
		if !slices.Contains(existing, id) && !slices.Contains(added, id) {
			added = append(added, id)
		}
	}
	for _, id := range existing {
		if !slices.Contains(groupIDs, id) {
			removed = append(removed, id)
		}
	}
	if len(added) == 0 && len(removed) == 0 {
		return nil
	}
	if err := lockLiveGroups(ctx, r.client, added); err != nil {
		return err
	}
	if len(removed) > 0 {
		if _, err := r.client.AccountGroup.Delete().Where(dbaccountgroup.AccountIDEQ(accountID), dbaccountgroup.GroupIDIn(removed...)).Exec(ctx); err != nil {
			return err
		}
	}
	for _, id := range added {
		if _, err := r.client.AccountGroup.Create().SetAccountID(accountID).SetGroupID(id).SetPriority(slices.Index(groupIDs, id) + 1).Save(ctx); err != nil {
			return err
		}
	}
	return enqueueSchedulerOutbox(ctx, r.sql, service.SchedulerOutboxEventAccountGroupsChanged, &accountID, nil, buildSchedulerGroupPayload(mergeGroupIDs(existing, groupIDs)))
}

// scopedAdminAccountPredicates 保证读取和导入候选查询使用相同的范围语义。
func scopedAdminAccountPredicates(policy adminaccess.Policy, permission string) []dbpredicate.Account {
	alternatives := []dbpredicate.Account{}
	for _, rule := range policy.RulesFor(permission) {
		if len(rule.AccountTypes) == 0 {
			continue
		}
		terms := []dbpredicate.Account{dbaccount.TypeIn(rule.AccountTypes...)}
		if len(rule.Platforms) > 0 {
			terms = append(terms, dbaccount.PlatformIn(rule.Platforms...))
		}
		if rule.AllGroups && !rule.IncludeUngrouped {
			terms = append(terms, dbaccount.HasAccountGroups())
		}
		if !rule.AllGroups {
			groups := []dbpredicate.Account{}
			if len(rule.GroupIDs) > 0 {
				groups = append(groups, dbaccount.HasAccountGroupsWith(dbaccountgroup.GroupIDIn(rule.GroupIDs...)))
			}
			if rule.IncludeUngrouped {
				groups = append(groups, dbaccount.Not(dbaccount.HasAccountGroups()))
			}
			if len(groups) == 0 {
				continue
			}
			terms = append(terms, dbaccount.Or(groups...))
		}
		alternatives = append(alternatives, dbaccount.And(terms...))
	}
	return alternatives
}

// ScopedAdminCodexCandidates 按导入身份逐级匹配，最多返回一个候选的身份字段。
// 不向应用加载其他账户的凭证；真正合并凭证仍在写事务锁内进行。
func (r *accountRepository) ScopedAdminCodexCandidates(ctx context.Context, identity service.ScopedCodexIdentity) ([]service.Account, error) {
	principal := adminaccess.FromContext(ctx)
	if principal == nil {
		return nil, fmt.Errorf("缺少受限身份")
	}
	scope := scopedAdminAccountPredicates(principal.Policy, "accounts.credentials")
	if len(scope) == 0 {
		return []service.Account{}, nil
	}
	for _, match := range scopedCodexIdentityPredicates(identity) {
		var rows []struct {
			ID          int64
			Credentials json.RawMessage
		}
		err := r.accountListFilteredQuery(service.PlatformOpenAI, service.AccountTypeOAuth, "", "", 0, "").
			Where(dbaccount.Or(scope...), match).Order(dbaccount.ByID(entsql.OrderDesc())).Limit(1).
			Select(dbaccount.FieldID).Aggregate(func(s *entsql.Selector) string {
			c := s.C(dbaccount.FieldCredentials)
			if IsMySQL() {
				return "JSON_OBJECT('chatgpt_account_id', JSON_EXTRACT(" + c + ", '$.chatgpt_account_id'), 'chatgpt_user_id', JSON_EXTRACT(" + c + ", '$.chatgpt_user_id'), 'email', JSON_EXTRACT(" + c + ", '$.email'), 'access_token', JSON_EXTRACT(" + c + ", '$.access_token')) AS credentials"
			}
			return "jsonb_build_object('chatgpt_account_id', " + c + "->'chatgpt_account_id', 'chatgpt_user_id', " + c + "->'chatgpt_user_id', 'email', " + c + "->'email', 'access_token', " + c + "->'access_token') AS credentials"
		}).Scan(ctx, &rows)
		if err != nil {
			return nil, err
		}
		if len(rows) != 0 {
			var credentials map[string]any
			if err := json.Unmarshal(rows[0].Credentials, &credentials); err != nil {
				return nil, err
			}
			return []service.Account{{ID: rows[0].ID, Credentials: credentials}}, nil
		}
	}
	return []service.Account{}, nil
}

// 与导入器的 account_user / user / email / access / account 优先级保持一致。
// account 回退必须排除明确属于其他用户的账户；仅 access token 和 Agent Identity 各有独立匹配规则。
func scopedCodexIdentityPredicates(identity service.ScopedCodexIdentity) []dbpredicate.Account {
	accountID, userID := strings.TrimSpace(identity.AccountID), strings.TrimSpace(identity.UserID)
	email, token := strings.ToLower(strings.TrimSpace(identity.Email)), strings.TrimSpace(identity.AccessToken)
	// 与 Go strings.TrimSpace 的 Unicode 空白集合一致，兼容旧凭证中的首尾空白。
	const whitespace = "\t\n\v\f\r \u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"
	field := func(key string) string {
		// 字段名均为下方固定常量；非法 JSON 类型按导入器规则视为空值。
		if IsMySQL() {
			return mysqlScopedCredentialField(key)
		}
		raw := `"accounts"."credentials"->'` + key + `'`
		value := `"accounts"."credentials"->>'` + key + `'`
		// 旧 JSON 数值经 Go 解码为 float64：保留同样的精度，展开指数并去掉尾随小数零。
		number := "trim_scale(((" + value + ")::double precision)::text::numeric)::text"
		return "btrim(CASE jsonb_typeof(" + raw + ") WHEN 'string' THEN " + value + " WHEN 'number' THEN " + number + " ELSE '' END, '" + whitespace + "')"
	}
	a, u, e, access := field("chatgpt_account_id"), field("chatgpt_user_id"), field("email"), field("access_token")
	match := func(expr string, args ...any) dbpredicate.Account {
		parts := strings.Split(expr, "?")
		return func(s *entsql.Selector) {
			s.Where(entsql.P(func(b *entsql.Builder) {
				for i, part := range parts {
					b.WriteString(part)
					if i < len(args) {
						b.Arg(args[i])
					}
				}
			}))
		}
	}
	predicates := []dbpredicate.Account{}
	if !identity.AgentIdentity && !identity.AccessTokenOnly {
		switch {
		case accountID != "" && userID != "":
			predicates = append(predicates, match(a+" = ? AND "+u+" = ?", accountID, userID))
		case userID != "":
			predicates = append(predicates, match(a+" = '' AND "+u+" = ?", userID))
		case accountID == "" && email != "":
			predicates = append(predicates, match(a+" = '' AND "+u+" = '' AND lower("+e+") = ?", email))
		}
	}
	if !identity.AgentIdentity && token != "" {
		predicates = append(predicates, match(access+" = ?", token))
	}
	if accountID != "" && (identity.AgentIdentity || !identity.AccessTokenOnly) {
		if userID == "" {
			predicates = append(predicates, match(a+" = ?", accountID))
		} else {
			predicates = append(predicates, match(a+" = ? AND ("+u+" = '' OR "+u+" = ?)", accountID, userID))
		}
	}
	return predicates
}

// mysqlScopedCredentialWhitespace 对齐 Go strings.TrimSpace / PG btrim 使用的空白集合：
// [[:space:]] 覆盖 ASCII 空白，其余按码点列出。反斜杠必须写两遍：SQL 词法会吃掉
// 未识别转义序列的前导反斜杠（单层 \x{2000} 会退化成字面 x{2000}，把 ICU 字符集
// 变成非法的 `}-x` 范围并抛 ER_REGEXP_INVALID_RANGE 3697），剩下的单层才是 ICU 语法。
const mysqlScopedCredentialWhitespace = `[[:space:]\\x{0085}\\x{00A0}\\x{1680}\\x{2000}-\\x{200A}\\x{2028}\\x{2029}\\x{202F}\\x{205F}\\x{3000}]`

// mysqlScopedCredentialField 是 PG 版凭证取值表达式的 MySQL 等价实现：
//   - ->'k' / ->>'k' → JSON_EXTRACT / JSON_UNQUOTE(JSON_EXTRACT)；
//   - jsonb_typeof → JSON_TYPE（大写枚举，number 细分为 INTEGER/DOUBLE/DECIMAL）；
//   - trim_scale(((v)::double precision)::text::numeric)::text →
//     CAST(CAST(v AS DOUBLE) AS DECIMAL(65,30)) 再裁掉尾随 0 与小数点
//     （实测逐值一致：1.0→1、1e7→10000000、18 位整数按 float64 精度展开成 123456789012345680）；
//   - btrim(x, <空白集合>) → REGEXP_REPLACE 裁剪首尾同类字符集（MySQL 无按字符集合的 TRIM）。
//
// 已知语义差：JSON 数值超出 DECIMAL(65,30) 可表示范围时取值为 NULL（PG 保留原值），
// 该情况只会让匹配落空；账户标识不可能是这种量级，按不命中处理。
func mysqlScopedCredentialField(key string) string {
	raw := "JSON_EXTRACT(`accounts`.`credentials`, '$." + key + "')"
	value := "JSON_UNQUOTE(" + raw + ")"
	number := "TRIM(TRAILING '.' FROM TRIM(TRAILING '0' FROM CAST(CAST(" + value + " AS DOUBLE) AS DECIMAL(65,30))))"
	return "REGEXP_REPLACE(CASE WHEN JSON_TYPE(" + raw + ") = 'STRING' THEN " + value +
		" WHEN JSON_TYPE(" + raw + ") IN ('INTEGER', 'DOUBLE', 'DECIMAL') THEN " + number +
		" ELSE '' END, '^" + mysqlScopedCredentialWhitespace + "+|" + mysqlScopedCredentialWhitespace + "+$', '')"
}
