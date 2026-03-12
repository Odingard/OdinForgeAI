-- OdinForge E2E Test Database Seed
-- Known credentials for breach chain testing (GTM Section 8.3)

USE testapp;

-- Users table with known test credentials
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(64) NOT NULL,
  email VARCHAR(128) NOT NULL,
  password_hash VARCHAR(256) NOT NULL,
  role VARCHAR(32) DEFAULT 'user',
  api_key VARCHAR(64),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users (username, email, password_hash, role, api_key) VALUES
  ('admin', 'admin@testapp.local', '$2b$10$fakehash_admin_testdb_pass_xyz789', 'admin', 'ak_test_admin_key_12345'),
  ('appuser', 'appuser@testapp.local', '$2b$10$fakehash_appuser_testdb_pass_xyz789', 'user', 'ak_test_user_key_67890'),
  ('backup_svc', 'backup@testapp.local', '$2b$10$fakehash_backup_svc_account', 'service', 'ak_test_svc_key_backup'),
  ('deploy_bot', 'deploy@testapp.local', '$2b$10$fakehash_deploy_bot_account', 'service', NULL);

-- Sessions table for credential extraction testing
CREATE TABLE IF NOT EXISTS sessions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  session_token VARCHAR(128) NOT NULL,
  ip_address VARCHAR(45),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

INSERT INTO sessions (user_id, session_token, ip_address, expires_at) VALUES
  (1, 'sess_admin_e2e_token_aabbccdd', '10.0.0.1', DATE_ADD(NOW(), INTERVAL 30 DAY)),
  (2, 'sess_user_e2e_token_eeffgghh', '10.0.0.2', DATE_ADD(NOW(), INTERVAL 7 DAY));

-- Config table with sensitive values (for Phase 2 credential extraction)
CREATE TABLE IF NOT EXISTS app_config (
  config_key VARCHAR(64) PRIMARY KEY,
  config_value TEXT NOT NULL,
  is_secret BOOLEAN DEFAULT FALSE
);

INSERT INTO app_config (config_key, config_value, is_secret) VALUES
  ('db_connection_string', 'mysql://appuser:testdb_pass_xyz789@localhost:3306/testapp', TRUE),
  ('aws_access_key_id', 'AKIAIOSFODNN7EXAMPLE', TRUE),
  ('aws_secret_access_key', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', TRUE),
  ('jwt_signing_secret', 'e2e-test-jwt-secret-not-for-production', TRUE),
  ('smtp_password', 'smtp_test_pass_xyz789', TRUE),
  ('app_name', 'TestApp E2E', FALSE),
  ('max_upload_size', '10485760', FALSE);

-- Network inventory for lateral movement testing
CREATE TABLE IF NOT EXISTS network_hosts (
  id INT AUTO_INCREMENT PRIMARY KEY,
  hostname VARCHAR(128) NOT NULL,
  ip_address VARCHAR(45) NOT NULL,
  os_type VARCHAR(32),
  services JSON,
  credentials_ref VARCHAR(64)
);

INSERT INTO network_hosts (hostname, ip_address, os_type, services, credentials_ref) VALUES
  ('web-server', '10.0.0.10', 'linux', '["http:80","https:443","ssh:22"]', 'cred-web-001'),
  ('db-server', '10.0.0.20', 'linux', '["mysql:3306","ssh:22"]', 'cred-db-001'),
  ('file-server', '10.0.0.30', 'windows', '["smb:445","rdp:3389"]', 'cred-file-001'),
  ('k8s-master', '10.0.0.40', 'linux', '["k8s-api:6443","ssh:22"]', 'cred-k8s-001'),
  ('backup-server', '10.0.0.50', 'linux', '["ssh:22","nfs:2049"]', 'cred-backup-001');

-- Audit log for replay verification
CREATE TABLE IF NOT EXISTS audit_log (
  id INT AUTO_INCREMENT PRIMARY KEY,
  action VARCHAR(64) NOT NULL,
  actor VARCHAR(64) NOT NULL,
  target VARCHAR(128),
  details TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO audit_log (action, actor, target, details) VALUES
  ('login', 'admin', 'web-ui', 'Successful login from 10.0.0.1'),
  ('config_change', 'deploy_bot', 'app_config', 'Updated jwt_signing_secret'),
  ('user_create', 'admin', 'backup_svc', 'Created service account');
