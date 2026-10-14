def build_query(table_name):
    # Called only internally as build_query("users") — table_name is a
    # hardcoded literal chosen by the developer, never derived from any
    # HTTP request. Untyped parameters aren't automatically user input.
    query = f"SELECT * FROM {table_name}"
    db.execute(query)

def run_report():
    build_query("users")
