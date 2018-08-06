from androguard.core.bytecodes.dvm import *
from androguard.core.analysis.analysis import *
from typing import List
from .API_Res import translate
from .analysis_result import AnalyzedApk
from .UsageAnalysisResult import UsageAnalysis
import json
import logging
import sys
import os


def backtrace_usage(analysis, usage, visited_xrefs=[]):
    # type: (Analysis, MethodClassAnalysis, List[MethodClassAnalysis]) -> List[EncodedMethod]
    if usage in visited_xrefs:
        # make sure that we don't end in a cyclic path
        return []
    elif "onRequestPermissionsResult" in usage.get_method().get_name():
        # succesfully backtraced path to permission request
        logging.debug("Found onRequestPermissionsResult")
        return [usage.get_method()]
    else:
        # Add the current usage to the xrefs already visited (empty list on first call by default)
        visited_xrefs += [usage]

        # If we do not have xrefs from this path won't lead to any result
        if not usage.get_xref_from():
            return []
        else:
            # Backtrace all XREFs from
            for (ref_class, ref_method, offset) in usage.get_xref_from():
                backtrace = backtrace_usage(analysis, analysis.get_method_analysis(ref_method), visited_xrefs)

                # If the result ever is not empty we found a path
                if backtrace:
                    logging.debug("Adding %s to path..." % str(usage.get_method()))
                    return [usage.get_method()] + backtrace

    # If not there exists no path
    return []


def analyze_usage(analysis, permission, perm_map):
    # type: (Analysis, str, dict) -> List[UsageAnalysis]

    analyzed_usages = []

    # check needed due to several differrent mappings
    if permission in perm_map.keys():

        logging.debug("Permission %s is a possible SDK/framework permission." % permission)

        # query the map for all methods that need this permission
        possible_usages = perm_map[permission]

        for possible_usage in possible_usages:

            logging.debug("Possible usage: %s" % possible_usage)

            # convert the name to androguard format and try to find the Method in our app
            (classname, methodname) = translate.translate(possible_usage)
            methods = analysis.find_methods(classname, methodname)

            if methods:
                for m in methods:
                    should_analyze = False

                    for (class_analysis, method, offset) in m.get_xref_from():
                        # We are only interested in usages that are called by external code
                        if not (method.get_class_name().startswith("Landroid") or
                                    method.get_class_name().startswith("Ljava") or
                                    method.get_class_name().startswith("Lkotlin")):
                            should_analyze = True

                    if should_analyze:
                        logging.debug("Usage in code: %s" % str(m))
                        logging.debug("Backtracing to onRequestPermissionResult")
                        # Try to backtrace a callgraph to the MainActivity
                        path = backtrace_usage(analysis, m)
                        if not path:
                            logging.debug("Backtracing not successful")
                        usage = UsageAnalysis(permission, m.get_method(), path, True)
                        # Avoid duplicates
                        if usage not in analyzed_usages:
                            analyzed_usages.append(usage)

    return analyzed_usages


def analyze_provider_usages(analysis, requested_permissions, perm_prov_map):
    # type: (Analysis, List[str], dict) -> List[UsageAnalysis]

    analyzed_usages = []

    # usually ContentProviders are queried via ContentResolver
    # so let's search for calls to methods of this class
    method_analysis_usages = analysis.find_methods(classname="Landroid/content/ContentResolver")

    to_consider = []

    for method_analysis in method_analysis_usages:
        # xrefs from are triples (ClassAnalysis, EncodedMethod, Hex)
        for (class_analysis, method, offset) in method_analysis.get_xref_from():
            # we want to filter callers which are part of the sdk or programming language
            # second tuple only for showing clearly that offset belongs to method
            if not (method.get_class_name().startswith("Landroid") or
                    method.get_class_name().startswith("Ljava") or
                    method.get_class_name().startswith("Lkotlin")):
                logging.debug("Found possible usage: %s" % str(method_analysis))
                to_consider += [(method_analysis, (method, offset))]

    # The to_consider list now contains all tuples of type
    # (MethodAnalysis, (EncodedMethod, Hex))
    # where the MethodAnalysis is the ContentResolver.query() method and the second one
    # the method where this call occurs together with the exact offset in the method


    for (usage, (caller, offset)) in to_consider:

        logging.debug("Analyzing %s..." % str(usage))

        analyzed_single_usage = []

        error = False

        # now check for each of the requested permissions (if it is a "Provider Permission")...

        for permission in requested_permissions:

            if permission not in perm_prov_map.keys():
                print("%s not in provider map" % permission)
                continue

            logging.debug("Checking permission %s..." % permission)


            # ... and all of their respective provider URIs...
            for uri in perm_prov_map[permission]["uri"]:

                logging.debug("Checking URI %s..." % uri)
                # ... if we can find the URI in the source code of the caller method
                # TODO: Is there a more effective way?

                try:
                    if uri in caller.get_source():

                        logging.debug("URI found: %s" % uri)

                        # we have to distinguish whether the permission protects rw, r or w access
                        if perm_prov_map[permission]["type"] == "rw":
                            # we don't need do analyze distinguish rw permissions further and
                            # are able to backtrace our method as usual
                            logging.debug("Type is RW, Backtracing to onRequestPermissionResult...")
                            if not path:
                                logging.debug("Backtracing not successful")

                            analyzed_usage = UsageAnalysis(permission, usage.get_method(), path, True)

                            if analyzed_usage not in analyzed_single_usage:
                                analyzed_single_usage.append(analyzed_usage)

                        elif perm_prov_map[permission]["type"] == "r":
                            logging.debug("Type is R")
                            # for read permissions we only need to consider the "query" method
                            if "query" in usage.get_method().get_name():
                                logging.debug("Method is query, Backtracing to onRequestPermissionResult")
                                path = backtrace_usage(analysis, usage)
                                if not path:
                                    logging.debug("Backtracing not successful")

                                analyzed_usage = UsageAnalysis(permission, usage.get_method(), path, True)

                                if analyzed_usage not in analyzed_single_usage:
                                    analyzed_single_usage.append(analyzed_usage)

                        elif perm_prov_map[permission]["type"] == "w":
                            logging.debug("Type is w")
                            # for write permissions we conside "insert", "update" and "delete"
                            if (("insert "in usage.get_method().get_name()) or
                                ("update" in usage.get_method().get_name()) or
                                ("delete" in usage.get_method().get_name())):
                                path = backtrace_usage(analysis, usage)
                                if not path:
                                    logging.debug("Backtracing not successful")

                                analyzed_usage = UsageAnalysis(permission, usage.get_method(), path, True)

                                if analyzed_usage not in analyzed_single_usage:
                                    analyzed_single_usage.append(analyzed_usage)

                        else:
                            mes = "Unknown permission type: %s" % (perm_prov_map[permission]["type"])
                            raise Exception(mes)
                except TypeError:
                    # Is sometimes thrown by Androguard
                    # Error by Androguard -> skip this caller
                    error = True
                    break

            if error:
                break

        if error:
            continue

        # if the single usage analysis list is empty this must be a usage that was for some reason not analyzable
        # so we create a "fake" UsageAnalysis to inform the user and let him check
        if len(analyzed_single_usage) == 0:

            reason = "Could not find a matching permission for the call to ContentResolver in:\n"
            reason += "%s->%s%s\n" % (caller.get_class_name(), caller.get_name(), caller.get_descriptor())
            reason += caller.get_source()
            logging.info("Adding UsageAnalysis for unknown permission")
            logging.info(reason)
            unknown_usage = UsageAnalysis(reason=reason)
            if unknown_usage not in analyzed_usages:
                analyzed_usages.append(unknown_usage)

        else:
            analyzed_usages += analyzed_single_usage

    print(8)

    return analyzed_usages


def run_usage_analysis(apk, analysis):
    # type: (AnalyzedApk, Analysis) -> AnalyzedApk

    # Get base path of permcrawl.py for loading the json files
    base_path = os.path.dirname(os.path.realpath(sys.argv[0]))

    # Load the permission-sdk-map and the permission-framework map from the resp. json files as dicts
    # Take car of the used workaround for circumventing Androguard's lack of target SDK 26 and above
    if apk.target_sdk > 25:
        shadow_target_sdk = 25
    else:
        shadow_target_sdk = apk.target_sdk

    with open(base_path + "/AnalysisUtils/"
              "API_Res/perm-sdk-map-api" + str(shadow_target_sdk) + ".json",  "r") as sdk_dict:
        perm_sdk_map = json.load(sdk_dict)

    if not perm_sdk_map:
        raise Exception("Could not load the permission-sdk mapping for API " + str(shadow_target_sdk))

    with open(base_path + "/AnalysisUtils/API_Res/perm-framework-map-api" + str(shadow_target_sdk) + ".json", "r") \
            as framework_dict:
        perm_framework_map = json.load(framework_dict)

    if not perm_framework_map:
        raise Exception("Could not load the permission-framework mapping for API " + str(shadow_target_sdk))

    with open(base_path + "/AnalysisUtils/API_Res/ContentProvider/perm-provider-map23.json",  "r") \
            as provider_dict:
        perm_provider_map = json.load(provider_dict)

    if not perm_provider_map:
        raise Exception("Could not load the permission-provider mapping for API " + str(shadow_target_sdk))

    usages = []

    for permission in apk.requested_permissions_from_manifest:

        logging.debug("Analyzing usages of SDK permissions...")
        usages += analyze_usage(analysis, permission, perm_sdk_map)
        logging.debug("Analyzing usages of framework permissions...")
        usages += analyze_usage(analysis, permission, perm_framework_map)

    logging.info("Analyzing usages of provider permissions")
    usages += analyze_provider_usages(analysis, apk.requested_permissions_from_manifest, perm_provider_map)
    logging.info("Finished usage analysis.")

    apk.analyzed_usages = usages

    sdk_dict.close()
    framework_dict.close()
    provider_dict.close()

    return apk
