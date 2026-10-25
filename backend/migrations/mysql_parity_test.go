package migrations

import (
	"io/fs"
	"sort"
	"strings"
	"testing"
)

// TestMySQLMigrationsMirrorPostgreSQL 钉住 mysql/ 目录与 PostgreSQL 迁移的一一对应关系：
// 上游新增/重命名 PG 迁移时，若忘记翻译同名 MySQL 文件，MySQL 实例会在启动迁移阶段
// 报 Unknown column / Table doesn't exist，而不是在这里报一个可读的失败。
func TestMySQLMigrationsMirrorPostgreSQL(t *testing.T) {
	pg, err := migrationNames(FS)
	if err != nil {
		t.Fatalf("list postgres migrations: %v", err)
	}
	my, err := migrationNames(MySQLFS)
	if err != nil {
		t.Fatalf("list mysql migrations: %v", err)
	}

	missing := []string{}
	for _, name := range pg {
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		if !hasName(my, name) {
			missing = append(missing, name)
		}
	}
	extra := []string{}
	for _, name := range my {
		if !hasName(pg, name) {
			extra = append(extra, name)
		}
	}

	if len(missing) > 0 {
		t.Errorf("mysql/ 缺少同名镜像迁移（需按 TRANSLATION_RULES.md 翻译）：%s", strings.Join(missing, ", "))
	}
	if len(extra) > 0 {
		t.Errorf("mysql/ 存在 PostgreSQL 没有的迁移：%s", strings.Join(extra, ", "))
	}
}

func migrationNames(fsys fs.FS) ([]string, error) {
	names, err := fs.Glob(fsys, "*.sql")
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}

func hasName(names []string, want string) bool {
	i := sort.SearchStrings(names, want)
	return i < len(names) && names[i] == want
}
