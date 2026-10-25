-- MySQL 方言版本（翻译自 ../247_scoped_admin_api_keys.sql）
-- 管理密钥独立存储，仅保存不可逆摘要，保留撤销记录用于审计。
--
-- 说明：TIMESTAMPTZ → DATETIME(3)；DEFAULT NOW() → DEFAULT CURRENT_TIMESTAMP(3)；
--       JSONB DEFAULT '[]'/'{}' → JSON DEFAULT ('[]')/DEFAULT ('{}')（8.0.13+ 表达式默认值）；
--       TEXT NOT NULL DEFAULT '' → DEFAULT ('')；
--       PG 内联 REFERENCES → 显式命名的 CONSTRAINT fk_xxx FOREIGN KEY（无 ON DELETE，语义同 NO ACTION）；
--       ADD COLUMN IF NOT EXISTS → 去掉 IF EXISTS（执行器保证单次执行）。

CREATE TABLE IF NOT EXISTS scoped_admin_api_keys (
    id           VARCHAR(24) PRIMARY KEY,
    name         VARCHAR(100) NOT NULL,
    description  TEXT NOT NULL DEFAULT (''),
    key_prefix   VARCHAR(64) NOT NULL,
    key_hash     VARCHAR(64) NOT NULL,
    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    expires_at   DATETIME(3) NULL,
    allowed_ips  JSON NOT NULL DEFAULT ('[]'),
    policy       JSON NOT NULL DEFAULT ('{}'),
    created_by   BIGINT NOT NULL,
    created_at   DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at   DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    last_used_at DATETIME(3) NULL,
    last_used_ip VARCHAR(64) NOT NULL DEFAULT '',
    revoked_at   DATETIME(3) NULL,
    CONSTRAINT fk_scoped_admin_api_keys_created_by FOREIGN KEY (created_by) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- 仅将已撤销管理密钥从列表移除，保留原记录与历史审计。
ALTER TABLE scoped_admin_api_keys
    ADD COLUMN deleted_at DATETIME(3) NULL;
