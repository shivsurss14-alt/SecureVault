-- Optional: the app creates these automatically on first run.
CREATE DATABASE IF NOT EXISTS securevault_db;
USE securevault_db;

CREATE TABLE IF NOT EXISTS vault_meta (
    id INT PRIMARY KEY,
    salt VARBINARY(16) NOT NULL,
    verifier CHAR(64) NOT NULL
);

CREATE TABLE IF NOT EXISTS entries (
    id INT AUTO_INCREMENT PRIMARY KEY,
    site VARCHAR(100) NOT NULL,
    username VARCHAR(100),
    password_enc TEXT NOT NULL,
    notes VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Demo query: shows passwords are stored encrypted
-- SELECT id, site, username, password_enc FROM entries;
