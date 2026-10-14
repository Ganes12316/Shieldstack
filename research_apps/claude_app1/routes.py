from fastapi import FastAPI
import sqlite3

app = FastAPI()

def get_db():
    return sqlite3.connect("app.db")

@app.delete("/api/users/{id}")
def delete_user(id: int):
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id = ?", (id,))
    conn.commit()
    return {"status": "deleted"}

@app.get("/api/search")
def search_users(name: str):
    conn = get_db()
    query = f"SELECT * FROM users WHERE name LIKE '%{name}%'"
    cursor = conn.execute(query)
    return cursor.fetchall()