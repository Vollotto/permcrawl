from androguard.androguard.misc import AnalyzeAPK

def invokeAndroguard(path):
    a, d, dx = AnalyzeAPK(path)
    return a, d, dx