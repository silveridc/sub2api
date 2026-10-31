-- MySQL 方言版本（翻译自 ../249_mcp_oauth.sql）
-- OAuth 客户端走公共客户端授权码 + S256 PKCE。不落库任何 client secret、
-- 授权码、访问令牌或刷新令牌的原文。
--
-- 说明：TIMESTAMPTZ → DATETIME(3)；BOOLEAN → TINYINT(1)；
--       PG 内联 REFERENCES ... ON DELETE CASCADE → 显式命名的 CONSTRAINT ... FOREIGN KEY ... ON DELETE CASCADE；
--       CREATE INDEX IF NOT EXISTS → 表内 KEY（MySQL 的 CREATE INDEX 不支持 IF NOT EXISTS，
--       执行器保证每个迁移文件只执行一次）；
--       client_id / resource / redirect_uri 为 TEXT 负载列，不参与索引，保持 TEXT 即可。

CREATE TABLE IF NOT EXISTS mcp_oauth_grants (
    id            VARCHAR(43) PRIMARY KEY,
    client_id     TEXT NOT NULL,
    client_name   VARCHAR(100) NOT NULL,
    user_id       BIGINT NOT NULL,
    token_version BIGINT NOT NULL,
    resource      TEXT NOT NULL,
    scope         VARCHAR(16) NOT NULL,
    read_only     TINYINT(1) NOT NULL DEFAULT 1,
    created_at    DATETIME(3) NOT NULL,
    expires_at    DATETIME(3) NOT NULL,
    last_used_at  DATETIME(3) NULL,
    revoked_at    DATETIME(3) NULL,
    KEY idx_mcp_oauth_grants_user_created (user_id, created_at DESC),
    KEY idx_mcp_oauth_grants_expiry (expires_at),
    CONSTRAINT chk_mcp_oauth_grants_scope CHECK (scope IN ('user', 'admin')),
    CONSTRAINT fk_mcp_oauth_grants_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS mcp_oauth_codes (
    code_hash      VARCHAR(64) PRIMARY KEY,
    grant_id       VARCHAR(43) NOT NULL,
    client_id      TEXT NOT NULL,
    redirect_uri   TEXT NOT NULL,
    resource       TEXT NOT NULL,
    code_challenge VARCHAR(43) NOT NULL,
    expires_at     DATETIME(3) NOT NULL,
    consumed_at    DATETIME(3) NULL,
    KEY idx_mcp_oauth_codes_grant (grant_id),
    CONSTRAINT fk_mcp_oauth_codes_grant FOREIGN KEY (grant_id) REFERENCES mcp_oauth_grants(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- 已消费的 refresh 摘要保留到授权被清理，重放时可吊销整个家族，
-- 包括轮换之后签发的访问令牌。
CREATE TABLE IF NOT EXISTS mcp_oauth_credentials (
    key_hash   VARCHAR(64) PRIMARY KEY,
    grant_id   VARCHAR(43) NOT NULL,
    kind       VARCHAR(8) NOT NULL,
    expires_at DATETIME(3) NOT NULL,
    used_at    DATETIME(3) NULL,
    KEY idx_mcp_oauth_credentials_grant (grant_id),
    CONSTRAINT chk_mcp_oauth_credentials_kind CHECK (kind IN ('access', 'refresh')),
    CONSTRAINT fk_mcp_oauth_credentials_grant FOREIGN KEY (grant_id) REFERENCES mcp_oauth_grants(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
