import yara

def run_yara_scan(file_path):
    # Run a YARA scan on the file path.
    rules = yara.compile(filepath="/path/to/yara/rules")
    matches = rules.match(file_path)
    return matches
