class Error(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.error_context = message
