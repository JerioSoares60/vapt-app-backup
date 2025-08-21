import sqlite3
db = r"Automation\\backend\\data.db"
con = sqlite3.connect(db)
print("Tables:")
for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'"):
    print(" -", row[0])
print("\\nRecent audit logs:")
for row in con.execute("SELECT id, user_email, action, created_at FROM audit_logs ORDER BY id DESC LIMIT 20"):
    print(row)
print("\\nRecent dashboard datasets:")
for row in con.execute("SELECT id, title, project_name, uploaded_by_email, uploaded_at FROM dashboard_datasets ORDER BY id DESC LIMIT 20"):
    print(row)
con.close()
