from .AnalysisUtils.analysis_result import AnalyzedApk
from .AnalysisUtils.RequestAnalysisResult import RequestAnalysis
from .AnalysisUtils.UsageAnalysisResult import UsageAnalysis
from .AnalysisUtils.AndroguardProject.androguard.androguard.core.analysis.analysis import Analysis
from .AnalysisUtils.AndroguardProject.androguard.androguard.misc import AnalyzeAPK
import os
import sys

analyzed_apks = 0

not_analyzable_apks = 0
analysis_errors = 0
target_sdk_too_low = 0
no_permissions_declared = 0


def analyze_results(directory):
    for file in os.listdir(directory):
        if file.endswith(".json"):
            with open(file, "r") as json_dict:
                eval_apk_from_json(json_dict)


def eval_apk_from_json(json):
    analysis = Analysis()

    a,d,dx = AnalyzeAPK(json["apk_path"])

    for vm in d:
        analysis.add(vm)

    analysis.create_xref()

    apk = AnalyzedApk.from_json(analysis, json)
    eval_single_analysis_result(apk)


def eval_single_analysis_result(analyzed_apk):
    # type: (AnalyzedApk) -> ()

    global analyzed_apks
    analyzed_apks += 1

    if not analyzed_apk.is_analyzable():
        global not_analyzable_apks
        not_analyzable_apks += 1

        if analyzed_apk.error:
            global analysis_errors
            analysis_errors += 1

        if analyzed_apk.target_sdk_too_low:
            global target_sdk_too_low
            target_sdk_too_low += 1

        if analyzed_apk.no_permission_declared:
            global no_permissions_declared
            no_permissions_declared += 1


def print_result():
    global analyzed_apks
    global not_analyzable_apks
    global analysis_errors
    global target_sdk_too_low
    global no_permissions_declared

    print("Overall analyzed %d out of %d APKs" % (analyzed_apks - not_analyzable_apks, analyzed_apks))
    print("Out of %d apps that could not be analyzed" % not_analyzable_apks)
    print("\t-\t%d apps declared a target SDK version lower than 23" % target_sdk_too_low)
    print("\t-\t%d apps declared no permissions in their manifest" % no_permissions_declared)
    print("\t-\t%d apps raised errors during analysis" % analysis_errors)

if __name__ == '__main__':
    analyze_results(sys.argv[1])
    print_result()