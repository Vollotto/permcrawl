from androguard.androguard.misc import AnalyzeAPK

def invoke_androguard(path):
    a, d, dx = AnalyzeAPK(path)
    return a, d, dx