from AnalysisUtils.AndroguardProject.androguard.generators.axplorer_to_androguard import *


def translate(s):
    """
    Translates a line from axplorer format into classname & methodname
    Note that the axplorer mappings in this package are already inverted; instead of method -> permission they give all
    protected methods for a given permission
    :param s: The axplorer String to translate
    :return: string, string
    """

    # use a reex to split the original axplorer line into classname, methodname, argument types and return type
    m = re.compile(r"^(.*)\.(.*)\((.*)\)(.*)")
    res = m.search(s)
    if res:
        clname, methodname, all_args, ret = res.groups()

        # As axplorer is used by Androguard too, we can use the methods that Androguard also uses
        args = " ".join(map(name_to_androguard, all_args.split(",")))

        clname = name_to_androguard(clname)
        ret = name_to_androguard(ret)

        # Now simply return classname and method name which is the only thing we need in our project
        return (clname, methodname)
    else:
        raise ValueError("what?")