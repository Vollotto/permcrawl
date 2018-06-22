import logging
import re
from .explanation_dict import *


def is_explanation(permission, explanation):
    # type: (str) -> bool
    logging.debug("Possible explanation %s" % explanation)

    if is_text(explanation):
        logging.debug("Is text...")
        return is_general_explanation(explanation) and is_specific_explanation(permission, explanation)

    return False


def is_text(explanation):
    # This re filters sentences in a natural language format
    # Adapted from: https://regex101.com/r/nG1gU7/27
    re_sentence = re.compile("(?<!\w\.\w.)(?<![A-Z][a-z]\.)((?<=\.|\?|\!)$)")

    return re_sentence.search(explanation)


def is_general_explanation(explanation):
    # convert the explanation completely in lowercase
    explanation_conv = explanation.lower()

    for term in basic_terms:
        if term in explanation_conv:
            logging.debug("Is general...")
            return True

    return False


def is_specific_explanation(permission, explanation):
    # convert the explanation completely in lowercase
    explanation_conv = explanation.lower()

    # special case for testing
    if not perm_specific_terms[permission]:
        return True

    for term in perm_specific_terms[permission]:
        if term in explanation_conv:
            return True

    return False