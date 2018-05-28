import logging

def is_explanation(explanation):
    # type: (str) -> bool
    logging.info("Possible explanation %s" % explanation)
    if "access is required" in explanation:
        return True
    return False
