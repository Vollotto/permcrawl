from androguard.misc import AnalyzeAPK
import logging


def invoke_androguard(path):
    logging.info("Starting androguard...")
    a, d, dx = AnalyzeAPK(path)
    return a, d, dx
