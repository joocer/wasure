from .wasure_scanner import wasure_scanner

class null_scanner(wasure_scanner):
    _record = None

    def __init__(self, record):
        _record = record

    def execute_scan(self):
        return None, None, None