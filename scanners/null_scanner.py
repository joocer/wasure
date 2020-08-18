from wasure_scanner import wasure_scanner

class null_scanner(wasure_scanner):

    @staticmethod
    def execute_scan(record):
        return None, None, None