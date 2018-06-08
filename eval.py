import os
import sys
import json

analyzed_apks = 0

not_analyzable_apks = 0
analysis_errors = 0
target_sdk_too_low = 0
no_permissions_declared = 0

api23 = 0
api24 = 0
api25 = 0


def analyze_results_from_json(directory):
    for file in os.listdir(directory):
        if file.endswith(".json"):
            try:
                json_dict = open(os.path.realpath(directory) + '/' + file, "r")
                # For performance reasons directly evaluate from the json dict
                # With this we skip invoking androguard again for obtaining an analysis instance
                # But we also cannot use the classes of our actual framework but need to work directly with json dicts
                eval_single_analysis_result_from_json(json.loads(json_dict.read()))
            except:
                print("Could not load %s" % file)


def eval_single_analysis_result_from_json(analyzed_apk):

    global analyzed_apks
    analyzed_apks += 1

    invalid_target_sdk =  analyzed_apk["target_sdk_too_low"]
    no_permission = analyzed_apk["no_permission"]
    error = analyzed_apk["error"]

    if invalid_target_sdk or no_permission or error:
        global not_analyzable_apks
        not_analyzable_apks += 1

        if error:
            global analysis_errors
            analysis_errors += 1

        if invalid_target_sdk:
            global target_sdk_too_low
            target_sdk_too_low += 1

        if no_permission:
            global no_permissions_declared
            no_permissions_declared += 1
        return

    if analyzed_apk["target_sdk"] == 23:
        global api23
        api23 += 1
    elif analyzed_apk["target_sdk"] == 24:
        global api24
        api24 += 1
    else:
        global api25
        api25 += 1


def print_result():
    global analyzed_apks
    global not_analyzable_apks
    global analysis_errors
    global target_sdk_too_low
    global no_permissions_declared
    global api23
    global api24
    global api25

    print("Overall analyzed %d out of %d APKs" % (analyzed_apks - not_analyzable_apks, analyzed_apks))
    print("Out of %d apps that could not be analyzed" % not_analyzable_apks)
    print("\t-\t%d apps declared a target SDK version lower than 23" % target_sdk_too_low)
    print("\t-\t%d apps declared no permissions in their manifest" % no_permissions_declared)
    print("\t-\t%d apps raised errors during analysis" % analysis_errors)
    print("Out of %d analyzed apps" % (analyzed_apks - not_analyzable_apks))
    print("\t-\t%d apps declare target SDK version 23" % api23)
    print("\t-\t%d apps declare target SDK version 24" % api24)
    print("\t-\t%d apps declare target SDK version 25 or higher" % api25)

if __name__ == '__main__':
    analyze_results_from_json(sys.argv[1])
    print_result()