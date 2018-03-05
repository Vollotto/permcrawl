import argparse
from AnalysisUtils.AndroguardProject.androguardStarter import invoke_androguard
from AnalysisUtils.filter import *

class AnalyzedApk:
    '''
        Represents an App which has been analyzed for permission requests and their usages
    '''

    def __init__(self):

        self.app_name = ""
        self.package_name = ""

        # Defaults make app not analyzable
        self.target_sdk = 0
        self.target_sdk_too_low = True
        self.no_permission_declared = True
        # Only Error is set to true by default since submodules set it to true if they face an error
        self.error = False

        self.requested_permissions_from_manifest = []


    def isAnalyzable(self):
        return not (self.target_sdk_too_low or self.no_permission_declared or self.error)


def analyze(path_to_apk):

    a, d, dx = invoke_androguard(path_to_apk)

    app_to_analyze = AnalyzedApk()

    app_to_analyze = init_basic_infos(a, app_to_analyze)

    app_to_analyze = filter_target_sdk(a, app_to_analyze)

    app_to_analyze = filter_manifest_permission_requests(a, app_to_analyze)

    if app_to_analyze.isAnalyzable():
        print "App %s:%s is analyzable" % (app_to_analyze.package_name, app_to_analyze.app_name)

        print "%s targets SDK Level %d" % (app_to_analyze.app_name, app_to_analyze.target_sdk)

        print "%s requests the following permissions:" % app_to_analyze.app_name

        for permission in app_to_analyze.requested_permissions_from_manifest:
            print permission

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="Test permission analysis")

    parser.add_argument("-i", "--input",
                        required=True, help="Path to apk file")
    args = parser.parse_args()

    analyze(args.input)

    exit(0)