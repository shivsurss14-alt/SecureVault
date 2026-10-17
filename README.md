# SecureVault - Encrypted Password Manager
Python + MySQL + Tkinter

## Folder
    SecureVault_Project/
      securevault_app.py   <- run this
      screens/             <- 5 background images (keep next to the .py file)
      requirements.txt
      schema.sql           <- optional (tables are auto-created)

## Run
1. Install and start MySQL.
2. pip install -r requirements.txt
3. Open securevault_app.py and set your MySQL user/password in DB_CONFIG.
4. python securevault_app.py

## Screen flow
1. Password screen (3 wrong attempts -> program exits). First run: create the master password.
2. Welcome screen -> "Welcome" button
3. Info screen (purpose, uses, advantages, conditions) -> "I Agree" button
4. Loading screen
5. "WELCOME TO SecureVault" -> "Start" button
6. Main dashboard (encrypted vault)

## Demo for the academy
1. Enter a wrong password twice (shows "Incorrect password, attempts left").
2. Enter the correct password and go through the screens.
3. Add 2-3 entries, use Generate and the strength meter.
4. In MySQL run: SELECT id, site, username, password_enc FROM entries;  (shows encrypted text)
5. Click Lock and log in again.

## Security design
- Master password is never stored.
- Key derived with PBKDF2-HMAC-SHA256 (200,000 rounds + random 16-byte salt).
- Only a SHA-256 hash of the derived key is stored to verify login.
- Passwords are encrypted with Fernet (AES-128-CBC + HMAC-SHA256) before saving to MySQL.
- Auto-lock after 120 s idle, clipboard cleared after 15 s, exit after 3 wrong attempts.
