@app.delete("/api/users/{id}")
def delete_user(id: int):
    db.delete_user(id)
    return {"status": "deleted"}

@app.get("/api/search")
def search_users(request):
    name = request.args.get("name")
    return _run_search(name)

def _run_search(name):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    db.execute(query)
    return db.fetchall()