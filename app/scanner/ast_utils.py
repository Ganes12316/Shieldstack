from tree_sitter import Language, Parser
import tree_sitter_javascript as tsjs
import tree_sitter_python as tspy
import tree_sitter_php as tsphp
PHP_LANGUAGE = Language(tsphp.language_php())



JS_LANGUAGE = Language(tsjs.language())
PY_LANGUAGE = Language(tspy.language())

def get_parser(file_suffix: str) -> Parser | None:
    if file_suffix in (".js", ".jsx", ".ts", ".tsx"):
        return Parser(JS_LANGUAGE)
    if file_suffix == ".py":
        return Parser(PY_LANGUAGE)
    if file_suffix == ".php":
        return Parser(PHP_LANGUAGE)
    return None

def node_text(node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")

def get_parser(file_suffix: str) -> Parser | None:
    if file_suffix in (".js", ".jsx", ".ts", ".tsx"):
        return Parser(JS_LANGUAGE)
    if file_suffix == ".py":
        return Parser(PY_LANGUAGE)
    if file_suffix == ".php":
        return Parser(PHP_LANGUAGE)
    return None