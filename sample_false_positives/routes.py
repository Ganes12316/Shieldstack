def list_users(sort_by: str):
    # Deliberately ignoring the caller's input for now — hardcoded safe default.
    sort_by = "name"
    query = f"SELECT * FROM users ORDER BY {sort_by}"
    db.execute(query)
