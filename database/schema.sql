-- ================================================================
--  SCAM SHIELD — COMPLETE DATABASE SCHEMA
--  Compatible with MySQL 5.7+ / XAMPP
--
--  HOW TO USE:
--  Option A (fresh install):  Run this whole file in phpMyAdmin
--  Option B (already have DB): See the ALTER TABLE section at the
--                               bottom to patch your existing tables
-- ================================================================

CREATE DATABASE IF NOT EXISTS scamshield
  DEFAULT CHARACTER SET utf8mb4
  DEFAULT COLLATE utf8mb4_unicode_ci;

USE scamshield;

-- ----------------------------------------------------------------
-- 1. USERS
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    user_id          VARCHAR(36)  PRIMARY KEY,
    name             VARCHAR(120) NOT NULL,
    email            VARCHAR(200) NOT NULL UNIQUE,
    password_hash    VARCHAR(256) NOT NULL,
    phone            VARCHAR(30)  DEFAULT NULL,
    date_of_birth    DATE         DEFAULT NULL,
    country          VARCHAR(80)  DEFAULT NULL,
    location         VARCHAR(120) DEFAULT NULL,
    timezone         VARCHAR(60)  DEFAULT 'EAT',
    occupation       VARCHAR(100) DEFAULT NULL,
    use_case         VARCHAR(200) DEFAULT NULL,
    bio              TEXT         DEFAULT NULL,
    auth_provider    VARCHAR(30)  DEFAULT 'email',
    role             ENUM('user','moderator','admin') DEFAULT 'user',
    status           ENUM('active','suspended','deleted') DEFAULT 'active',
    plan_id          VARCHAR(36)  DEFAULT NULL,
    scan_count       INT          DEFAULT 0,
    scans_this_month INT          DEFAULT 0,
    created_at       DATETIME     DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- ----------------------------------------------------------------
-- 2. ADMIN USERS
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS admin_users (
    admin_id      VARCHAR(36)  PRIMARY KEY DEFAULT (UUID()),
    admin_code    VARCHAR(20)  NOT NULL UNIQUE,
    name          VARCHAR(120) NOT NULL,
    email         VARCHAR(200) NOT NULL UNIQUE,
    password_hash VARCHAR(256) NOT NULL,
    role          ENUM('superadmin','admin','moderator') DEFAULT 'admin',
    is_active     TINYINT(1)   DEFAULT 1,
    created_at    DATETIME     DEFAULT CURRENT_TIMESTAMP
);

-- Default admin account  (password: admin123  — CHANGE THIS!)
INSERT IGNORE INTO admin_users (admin_id, admin_code, name, email, password_hash, role)
VALUES (UUID(), 'ADMIN001', 'System Admin', 'admin@scamshield.com', 'admin123', 'superadmin');

-- ----------------------------------------------------------------
-- 3. SCAN LOGS
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_logs (
    scan_id          VARCHAR(36)   PRIMARY KEY,
    user_id          VARCHAR(36)   NOT NULL,
    input_text       TEXT          NOT NULL,
    scan_type        ENUM('SMS','Email','URL','WhatsApp','Phone') DEFAULT 'SMS',
    result           ENUM('SCAM','SAFE','UNKNOWN') NOT NULL,
    confidence_score DECIMAL(5,2)  DEFAULT 0.00,
    risk_level       ENUM('Low','Medium','High') DEFAULT 'Low',
    engine_version   VARCHAR(20)   DEFAULT 'v1.0',
    ml_score         DECIMAL(5,4)  DEFAULT NULL  COMMENT 'Raw ML model score 0-1',
    rule_score       DECIMAL(5,4)  DEFAULT NULL  COMMENT 'Rule-based score 0-1',
    triggered_rules  JSON          DEFAULT NULL,
    duration_ms      INT           DEFAULT NULL,
    created_at       DATETIME      DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- ----------------------------------------------------------------
-- 4. REPORTS  (user-submitted scam reports)
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS reports (
    report_id        VARCHAR(20)   PRIMARY KEY,
    user_id          VARCHAR(36)   NOT NULL,
    scan_id          VARCHAR(36)   DEFAULT NULL,
    category         VARCHAR(80)   NOT NULL,
    risk_level       ENUM('Low','Medium','High') DEFAULT 'Medium',
    status           ENUM('Pending','Under Review','Resolved','Dismissed') DEFAULT 'Pending',
    description      TEXT          DEFAULT NULL,
    reported_number  VARCHAR(30)   DEFAULT NULL,
    reported_url     VARCHAR(2048) DEFAULT NULL,
    amount_lost      DECIMAL(12,2) DEFAULT NULL,
    currency         VARCHAR(10)   DEFAULT 'KES',
    resolution_notes TEXT          DEFAULT NULL,
    created_at       DATETIME      DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME      DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- ----------------------------------------------------------------
-- 5. BANNED KEYWORDS  (power the scan engine)
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS banned_keywords (
    keyword_id VARCHAR(36)  PRIMARY KEY,
    keyword    VARCHAR(255) NOT NULL UNIQUE,
    weight     DECIMAL(3,2) DEFAULT 0.50 COMMENT '0.0 – 1.0, higher = more suspicious',
    category   VARCHAR(80)  DEFAULT 'general',
    is_active  TINYINT(1)   DEFAULT 1,
    created_at DATETIME     DEFAULT CURRENT_TIMESTAMP
);

-- Seed keywords
INSERT IGNORE INTO banned_keywords (keyword_id, keyword, weight, category) VALUES
(UUID(), 'you have won',                    1.0, 'lottery'),
(UUID(), 'claim your prize',                1.0, 'lottery'),
(UUID(), 'congratulations you have been selected', 1.0, 'lottery'),
(UUID(), 'free money',                      1.0, 'fraud'),
(UUID(), 'nigerian prince',                 1.0, 'advance_fee'),
(UUID(), 'inheritance funds',               0.9, 'advance_fee'),
(UUID(), 'your account has been suspended', 0.9, 'phishing'),
(UUID(), 'mpesa pin',                       0.9, 'phishing'),
(UUID(), 'safaricom account suspended',     0.95,'phishing'),
(UUID(), 'kcb account blocked',             0.95,'phishing'),
(UUID(), 'equity bank verification',        0.9, 'phishing'),
(UUID(), 'send your pin',                   0.9, 'phishing'),
(UUID(), 'bitcoin payment',                 0.9, 'crypto'),
(UUID(), 'gift card',                       0.8, 'fraud'),
(UUID(), 'send money',                      0.8, 'fraud'),
(UUID(), 'urgent action required',          0.8, 'urgency'),
(UUID(), 'click here immediately',          0.8, 'phishing'),
(UUID(), 'wire transfer',                   0.7, 'fraud'),
(UUID(), 'verify your account',             0.7, 'phishing'),
(UUID(), 'limited time offer',              0.5, 'urgency'),
(UUID(), 'act now',                         0.6, 'urgency'),
(UUID(), 'no credit check',                 0.6, 'fraud'),
(UUID(), '100% guaranteed',                 0.7, 'fraud');

-- ----------------------------------------------------------------
-- 6. SUBSCRIPTION PLANS
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS subscription_plans (
    plan_id      VARCHAR(36)  PRIMARY KEY DEFAULT (UUID()),
    name         VARCHAR(80)  NOT NULL,
    price        DECIMAL(8,2) DEFAULT 0.00,
    currency     VARCHAR(10)  DEFAULT 'KES',
    scan_limit   INT          DEFAULT 10   COMMENT '-1 = unlimited',
    features     JSON         DEFAULT NULL,
    is_active    TINYINT(1)   DEFAULT 1,
    sort_order   INT          DEFAULT 0,
    created_at   DATETIME     DEFAULT CURRENT_TIMESTAMP
);

INSERT IGNORE INTO subscription_plans (plan_id, name, price, scan_limit, sort_order, is_active) VALUES
(UUID(), 'Free',       0,    10,  1, 1),
(UUID(), 'Basic',      499,  100, 2, 1),
(UUID(), 'Pro',        999,  500, 3, 1),
(UUID(), 'Enterprise', 2999, -1,  4, 1);

-- ----------------------------------------------------------------
-- 7. NOTIFICATIONS
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS notifications (
    notif_id   INT AUTO_INCREMENT PRIMARY KEY,
    user_id    VARCHAR(36)  NOT NULL,
    type       VARCHAR(40)  DEFAULT 'info',
    title      VARCHAR(200) NOT NULL,
    body       TEXT         DEFAULT NULL,
    is_read    TINYINT(1)   DEFAULT 0,
    created_at DATETIME     DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- ----------------------------------------------------------------
-- 8. INBOX MESSAGES  (contact form submissions)
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS inbox_messages (
    message_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id    VARCHAR(36)  DEFAULT NULL,
    type       VARCHAR(40)  DEFAULT 'contact',
    category   VARCHAR(80)  DEFAULT 'General',
    from_name  VARCHAR(120) DEFAULT NULL,
    from_email VARCHAR(200) DEFAULT NULL,
    from_phone VARCHAR(30)  DEFAULT NULL,
    subject    VARCHAR(300) DEFAULT NULL,
    body       TEXT         DEFAULT NULL,
    priority   ENUM('Normal','High','Urgent') DEFAULT 'Normal',
    status     ENUM('Unread','Pending','Resolved','Dismissed') DEFAULT 'Unread',
    is_unread  TINYINT(1)   DEFAULT 1,
    created_at DATETIME     DEFAULT CURRENT_TIMESTAMP
);

-- ----------------------------------------------------------------
-- 9. THREAT LIBRARY
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS threat_library (
    threat_id    VARCHAR(20)  PRIMARY KEY,
    name         VARCHAR(200) NOT NULL,
    category     VARCHAR(80)  DEFAULT NULL,
    severity     ENUM('Low','Medium','High','Critical') DEFAULT 'Medium',
    description  TEXT         DEFAULT NULL,
    indicators   JSON         DEFAULT NULL,
    report_count INT          DEFAULT 0,
    status       ENUM('New','Active','Monitoring','Resolved') DEFAULT 'New',
    created_at   DATETIME     DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Seed a few known threats
INSERT IGNORE INTO threat_library (threat_id, name, category, severity, report_count, status) VALUES
('THR-001', 'MPESA PIN Phishing',          'Phishing',  'Critical', 0, 'Active'),
('THR-002', 'Fake Lottery SMS',             'Lottery',   'High',     0, 'Active'),
('THR-003', 'Safaricom Impersonation',      'Phishing',  'High',     0, 'Active'),
('THR-004', 'Advance Fee (419) Fraud',      'Fraud',     'High',     0, 'Active'),
('THR-005', 'Crypto Investment Scam',       'Crypto',    'Medium',   0, 'Monitoring');

-- ----------------------------------------------------------------
-- 10. AUDIT LOG
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
    log_id     VARCHAR(36)  PRIMARY KEY,
    admin_id   VARCHAR(36)  DEFAULT NULL,
    admin_name VARCHAR(120) DEFAULT NULL,
    action     VARCHAR(200) NOT NULL,
    target     VARCHAR(200) DEFAULT NULL,
    severity   ENUM('info','warn','success','danger') DEFAULT 'info',
    ip_address VARCHAR(45)  DEFAULT NULL,
    created_at DATETIME     DEFAULT CURRENT_TIMESTAMP
);


-- ================================================================
--  MODIFY EXISTING DATABASE — RUN THESE IF YOU ALREADY HAVE TABLES
--  Each statement uses IF NOT EXISTS / IGNORE so it is safe to
--  run even if the column / table already exists.
-- ================================================================

-- ── users: add any missing columns ──────────────────────────────
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS phone            VARCHAR(30)  DEFAULT NULL AFTER password_hash,
    ADD COLUMN IF NOT EXISTS date_of_birth    DATE         DEFAULT NULL AFTER phone,
    ADD COLUMN IF NOT EXISTS country          VARCHAR(80)  DEFAULT NULL AFTER date_of_birth,
    ADD COLUMN IF NOT EXISTS location         VARCHAR(120) DEFAULT NULL AFTER country,
    ADD COLUMN IF NOT EXISTS timezone         VARCHAR(60)  DEFAULT 'EAT' AFTER location,
    ADD COLUMN IF NOT EXISTS occupation       VARCHAR(100) DEFAULT NULL AFTER timezone,
    ADD COLUMN IF NOT EXISTS use_case         VARCHAR(200) DEFAULT NULL AFTER occupation,
    ADD COLUMN IF NOT EXISTS bio              TEXT         DEFAULT NULL AFTER use_case,
    ADD COLUMN IF NOT EXISTS scans_this_month INT          DEFAULT 0   AFTER scan_count;

-- ── scan_logs: add ML columns if missing ────────────────────────
ALTER TABLE scan_logs
    ADD COLUMN IF NOT EXISTS ml_score        DECIMAL(5,4) DEFAULT NULL AFTER engine_version,
    ADD COLUMN IF NOT EXISTS rule_score      DECIMAL(5,4) DEFAULT NULL AFTER ml_score,
    ADD COLUMN IF NOT EXISTS triggered_rules JSON         DEFAULT NULL AFTER rule_score,
    ADD COLUMN IF NOT EXISTS duration_ms     INT          DEFAULT NULL AFTER triggered_rules;

-- ── reports: add resolution_notes if missing ────────────────────
ALTER TABLE reports
    ADD COLUMN IF NOT EXISTS resolution_notes TEXT DEFAULT NULL AFTER currency;