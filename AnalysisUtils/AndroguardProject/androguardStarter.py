from androguard.misc import AnalyzeAPK
import logging


def invoke_androguard(path):
    """
    Invokes the Androguard framework by using the AnalyzeAPK method
    :param path: The path of the APK file to analyze
    :return: Return the :class:`~androguard.androguard.core.bytecodes.apk.APK`, list of :class:`~androguard.androguard.core.bytecodes.dvm.DalvikVMFormat`,
    and :class:`~androguard.androguard.core.analysis.analysis.Analysis` objects
    """
    logging.info("Starting androguard...")
    a, d, dx = AnalyzeAPK(path)
    return a, d, dx
