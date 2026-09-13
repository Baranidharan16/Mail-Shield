import sqlite3

conn = sqlite3.connect('backend/forensics.db')
cursor = conn.cursor()
cursor.execute('PRAGMA table_info(gmail_accounts)')
cols = [r[1] for r in cursor.fetchall()]
print('Existing:', cols)

if 'google_account_email' not in cols:
    cursor.execute('ALTER TABLE gmail_accounts ADD COLUMN google_account_email VARCHAR(255)')
    print('Added google_account_email')

if 'provider' not in cols:
    cursor.execute("ALTER TABLE gmail_accounts ADD COLUMN provider VARCHAR(50) DEFAULT 'google'")
    print('Added provider')

if 'token_expiry' not in cols:
    cursor.execute('ALTER TABLE gmail_accounts ADD COLUMN token_expiry VARCHAR(64)')
    print('Added token_expiry')

conn.commit()
cursor.execute('PRAGMA table_info(gmail_accounts)')
print('Updated:', [r[1] for r in cursor.fetchall()])
conn.close()
