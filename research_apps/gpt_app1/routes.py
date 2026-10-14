from fastapi import FastAPI, Query
import sqlite3

app = FastAPI()

def get_connection():
    return sqlite3.connect("app.db")

@app.delete("/api/users/{id}")
def delete_user(id: int):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    return {"message": "User deleted successfully"}

@app.get("/api/search")
def search_users(name: str = Query(...)):
    conn = get_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE name LIKE '%" + name + "%'"
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return {"results": results}