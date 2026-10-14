@app.delete("/api/users/{id}")
@require_auth
def delete_user(id: int):
    db.delete_user(id)
    return {"status": "deleted"}

@app.get("/api/search")
def search_users(request):
    name = request.args.get("name")
    return db.execute("SELECT * FROM users WHERE name = %s", (name,))