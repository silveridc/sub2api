-- MySQL 方言版本（翻译自 ../248_group_image_count_billing.sql）
-- 翻译说明：`groups` 是 MySQL 8 保留字，加反引号；去掉 ADD COLUMN IF NOT EXISTS；
--           COMMENT ON COLUMN 整句跳过（MySQL 需重建整列定义，风险大于收益）。

-- 分组级按张计费开关：仅 OpenAI 与 Composite 分组使用。
ALTER TABLE `groups`
    ADD COLUMN image_count_billing BOOLEAN NOT NULL DEFAULT FALSE;
-- (comment skipped)
