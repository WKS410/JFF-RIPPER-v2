import logging
import coloredlogs

LOG_FORMAT = "{asctime} [{levelname[0]}] {name} : {message}"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
LOG_STYLE = "{"


class Logger():
    def __init__(self,service,log_level):
        self.service = service
        self.log_level = log_level

    def set_logger(self):
        logger1 = logging.getLogger(self.service)
        coloredlogs.install(self.log_level, fmt=LOG_FORMAT, datefmt=LOG_DATE_FORMAT, style=LOG_STYLE)
        return logger1