from  AnalysisUtils.AndroguardProject.androguard.generators.axplorer_to_androguard import *

def translate(s):
    # reanslates a line in axplorer format into classname & methodname
    m = re.compile(r"^(.*)\.(.*)\((.*)\)(.*)")
    res = m.search(s)
    if res:
        clname, methodname, all_args, ret = res.groups()
        args = " ".join(map(name_to_androguard, all_args.split(",")))

        clname = name_to_androguard(clname)
        ret = name_to_androguard(ret)

        return (clname, methodname)
    else:
        raise ValueError("what?")