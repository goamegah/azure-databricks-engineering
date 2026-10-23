import logging

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(name)s - %(lineno)d - %(message)s"
DATE_FORMAT = "%Y-%m-%d %T"


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers: # if already exists return logger
        return logger

    logger.setLevel(logging.INFO)
    formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger