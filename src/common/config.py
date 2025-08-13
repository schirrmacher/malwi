"""Configuration constants for malwi."""

# Supported file extensions for analysis
SUPPORTED_EXTENSIONS = ["py", "js", "mjs", "cjs"]

# Language mappings based on file extensions
EXTENSION_TO_LANGUAGE = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
}

# Comment prefixes for different file extensions (used in code output format)
EXTENSION_COMMENT_PREFIX = {
    ".py": "#",
    ".js": "//",
    ".mjs": "//",
    ".cjs": "//",
}
