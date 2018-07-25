import logging
import re
from typing import List

from androguard.core.analysis.analysis import *
from androguard.core.bytecodes.dvm import *

from .RequestAnalysisResult import RequestAnalysis
from .analysis_result import AnalyzedApk
from .ExplanationAnalysis.explanation_analysis import is_explanation


def backtrace_request(analysis, request, main_activity, visited_xrefs=[]):
    # type: (Analysis, MethodClassAnalysis, str, List[MethodClassAnalysis]) -> List[EncodedMethod]
    logging.debug("Searching for %s" % main_activity)

    if request in visited_xrefs:
        # this is a cycle... abort
        return []
    elif main_activity in request.get_method().get_class_name():
        # successfully backtraced path to permission request
        logging.info("Found MainActivity")
        return [request.get_method()]
    else:
        # Add the current usage to the xrefs already visited (empty list on first call by default)
        visited_xrefs += [request]

        # If we do not have xrefs from this path won't lead to any result
        if not request.get_xref_from():
            return []
        else:
            # Backtrace all XREFs from
            for (ref_class, ref_method, offset) in request.get_xref_from():
                backtrace = backtrace_request(analysis, analysis.get_method_analysis(ref_method),
                                              main_activity, visited_xrefs)

                # If the result ever is not empty we found a path
                if backtrace:
                    logging.debug("Adding %s to path..." % str(request.get_method()))
                    return [request.get_method()] + backtrace

    # If not there exists no path
    return []


def find_explanations(apk, analysis, request):
    # type: (APK, Analysis, RequestAnalysis) -> List[str]

    logging.debug("Searching possible explanations...")
    logging.debug("Searching in code...")

    possible_explanations = []

    # Maybe we have an explanation string directly in the code (constant, hardcoded,...)
    for str_analysis in analysis.get_strings():
        # We need the Strings used in the same method that calls our permission
        for (classobj, methodobj) in str_analysis.get_xref_from():
            # Also we need to check whether the String is really an explanation
            if methodobj == request.caller and is_explanation(request.permission, str_analysis.get_value()):
                logging.info("String analysis object in requesting method: \n%s" % repr(str_analysis))
                possible_explanations.append(str_analysis.get_value())

    logging.debug("Searching used string resources...")
    # Maybe there is a string ressource used as explanation
    # We can find them by searching for resource ids that are used in the method that requests the permission
    res_id = re.compile("\d{10}")
    ids_in_code = res_id.findall(request.caller.get_source())
    logging.debug("Found IDs: %s" % ids_in_code)

    # Take all string resources from the APK
    str_resources = apk.get_android_resources().get_resolved_strings()[apk.get_package()]['DEFAULT']
    logging.debug("Resolved Strings: %s" % str_resources)

    for str_id in ids_in_code:
        str_id = int(str_id)
        # Check if the id belongs to a resolved string resource
        if str_id in str_resources.keys():
            logging.info("Checking resolved String resource...\n%s" % str_resources[str_id])
            # Now check if the string is an explanation why a permission is needed
            if is_explanation(request.permission, str_resources[str_id]):
                possible_explanations.append(str_resources[str_id])

    return possible_explanations


def analyze_requests(apk, analysis, requested_permissions, main_activity):
    # type: (APK, Analysis, List[str], str) -> List[RequestAnalysis]

    logging.info("Creating XREFs...")
    analysis.create_xref()

    # List for RequestAnalysis objects to return
    analyzed_requests = []

    # first try to use Androguards' StringAnalysis
    for analyzed_string in analysis.get_strings():
        if analyzed_string.get_value() in requested_permissions:

            for (class_analysis, method) in analyzed_string.get_xref_from():
                analyzed_requests = find_requests_by_string_analysis(analysis, analysis.get_method_analysis(method),
                                                                     analyzed_requests, analyzed_string.get_value(),
                                                                     main_activity)

    # get all methods called "requestPermissions" from Androguard Analysis
    # Other way to identify requests...
    # TODO: How to cope with dynamic args?
    requests = analysis.find_methods(methodname="requestPermission")

    for req in requests:
        req = req  # type: MethodClassAnalysis
        logging.debug("Request:\n %s" % str(req))

        # Default value
        unknown_perm = True

        # The requesting method must be part of the SDK
        # if not req.get_method().get_class_name().startswith("Landroid"):
        #    continue

        # Get all xrefs from that are not part of the API
        for (ref_class, xref, offset) in req.get_xref_from():
            xref = xref  # type: EncodedMethod
            logging.debug("XREF from: %s" % str(xref))

            if (xref.get_class_name().startswith("Landroid") or
                    xref.get_class_name().startswith("Ljava") or
                    xref.get_class_name().startswith("Lkotlin")):
                # filter requests that are part of the SDK or language
                continue

            for permission in requested_permissions:

                logging.debug("Checking permission %s" % permission)

                if permission in xref.get_source():

                    unknown_perm = False

                    logging.debug("Found permission %s\n%s" % (permission, xref.get_source()))

                    # We have found the request for the declared permission
                    # Try to backtrace the request to MainActivity
                    path = backtrace_request(analysis, req, main_activity)
                    analyzed_req = RequestAnalysis(permission=permission, method=req.get_method(),
                                                   caller=xref, path=path)
                    if analyzed_req not in analyzed_requests:
                        analyzed_requests.append(analyzed_req)
    #
    #         # for permission in requested_permissions:
    #         #
    #         #     logging.debug("Checking permission %s" % permission)
    #         #
    #         #     try:
    #         #         if permission in parent_ref_class.get_vm_class().source():
    #         #
    #         #             #unknown_perm = False
    #         #
    #         #             logging.debug("Found permission %s\n%s" % (permission, parent_xref.get_source()))
    #         #
    #         #             # We have found the request for the declared permission
    #         #             # Try to backtrace the request to MainActivity
    #         #             path = backtrace_request(analysis, req, main_activity)
    #         #             analyzed_req = RequestAnalysis(permission=permission, method=req.get_method(),
    #         #                                            caller=xref, path=path)
    #         #             if analyzed_req not in analyzed_requests:
    #         #                 analyzed_requests.append(analyzed_req)
    #         #
    #         #     except TypeError:
    #         #         # if parent_ref_class.get_vm_class returns None we get a TypeError
    #         #         break
    #
        #if unknown_perm:
        # We did not found the permission in the source code of any xref
        # So we go again through all xrefs and serach for string ids
        # Get all xrefs from that are not part of the API
        for (ref_class, xref, offset) in req.get_xref_from():
            xref = xref  # type: EncodedMethod
            logging.info("Searching used string resources...")
            # Maybe there is a string ressource used as permission
            # We can find them by searching for resource ids that are used in the method
            # that requests the permission
            res_id = re.compile("\d{10}")
            ids_in_code = res_id.findall(xref.get_source())
            logging.debug("Found IDs: %s" % ids_in_code)

            # Take all string resources from the APK
            str_resources = apk.get_android_resources().get_resolved_strings()[apk.get_package()]['DEFAULT']
            logging.debug("Resolved Strings: %s" % str_resources)

            for str_id in ids_in_code:
                str_id = int(str_id)
                # Check if the id belongs to a resolved string resource
                if str_id in str_resources.keys():
                    logging.debug("Checking resolved String resource...\n%s" % str_resources[str_id])
                    # Now check if the string is a used permission
                    if str_resources[str_id] in requested_permissions:
                        logging.debug("Found permission %s" % str_resources[str_id])
                        unknown_perm = False
                        path = backtrace_request(analysis, req, main_activity)
                        analyzed_req = RequestAnalysis(permission=str_resources[str_id], method=req.get_method(),
                                                       caller=xref, path=path)

                        if analyzed_req not in analyzed_requests:
                            analyzed_requests.append(analyzed_req)
    #     #else:
    #     #    continue
    #
    #     #if unknown_perm:
    #     # Still no match, let's go some xrefs upwards
    #     # Get all xrefs from that are not part of the API
    #     # for (ref_class, xref, offset) in req.get_xref_from():
    #     #     xref = xref  # type: EncodedMethod
    #     #     logging.debug("XREF from: %s" % str(xref))
    #     #
    #     #     if (xref.get_class_name().startswith("Landroid") or
    #     #             xref.get_class_name().startswith("Ljava") or
    #     #             xref.get_class_name().startswith("Lkotlin")):
    #     #         # filter requests that are part of the SDK or language
    #     #         continue
    #     #
    #     #     xref_ana = analysis.get_method_analysis(xref) # type: MethodClassAnalysis
    #     #
    #     #     for (parent_ref_class, parent_xref, parent_offset) in xref_ana.get_xref_from():
    #     #         for permission in requested_permissions:
    #     #
    #     #             logging.debug("Checking permission %s" % permission)
    #     #
    #     #             if permission in parent_xref.get_source():
    #     #
    #     #                 unknown_perm = False
    #     #
    #     #                 logging.debug("Found permission %s\n%s" % (permission, parent_xref.get_source()))
    #     #
    #     #                 # We have found the request for the declared permission
    #     #                 # Try to backtrace the request to MainActivity
    #     #                 path = backtrace_request(analysis, req, main_activity)
    #     #                 analyzed_req = RequestAnalysis(permission=permission, method=req.get_method(),
    #     #                                                caller=xref, path=path)
    #     #                 if analyzed_req not in analyzed_requests:
    #     #                     analyzed_requests.append(analyzed_req)
    #
    #             # empirical evaluation showed that this is not enough, we need to go one step above
    #             # parent_xref_ana = analysis.get_method_analysis(parent_xref) # type: MethodClassAnalysis
    #             #
    #             # for (grandparent_ref_class, grandparent_xref, grandparent_offset) in parent_xref_ana.get_xref_from():
    #             #     for permission in requested_permissions:
    #             #
    #             #         logging.debug("Checking permission %s" % permission)
    #             #
    #             #         if permission in grandparent_xref.get_source():
    #             #
    #             #             logging.debug("Found permission %s\n%s" % (permission, grandparent_xref.get_source()))
    #             #
    #             #             # We have found the request for the declared permission
    #             #             # Try to backtrace the request to MainActivity
    #             #             path = backtrace_request(analysis, req, main_activity)
    #             #             analyzed_req = RequestAnalysis(permission=permission, method=req.get_method(),
    #             #                                            caller=xref, path=path)
    #             #             if analyzed_req not in analyzed_requests:
    #             #                 analyzed_requests.append(analyzed_req)
    #
    #
    #     #else:
    #     #    continue
    #
        #if unknown_perm:
        #Still no match
        #Try to relate the permission to the request via StringAnalysis
        for (ref_class, xref, offset) in req.get_xref_from():
            xref = xref  # type: EncodedMethod

            # First, take the base class from the caller
            # Follows the scheme: Ltld/package/subpackage/class$subclass > Split at $
            base_class = xref.get_class_name().split("$")[0]

            # Now, let's try to invoke Androguard's String Analysis for all the permissions
            for permission in requested_permissions:
                for sa in analysis.get_strings():
                    if permission in sa.get_value():
                        # found a StringAnalysis instance that seems to represent our permission
                        # so let's check the XREF set
                        for (class_analysis, method) in sa.get_xref_from():
                            # again take the base class and if we have a match treat it as positive result
                            if method.get_class_name().split("$")[0] == base_class:
                                logging.info("Found permission %s by base class comparison.\n" % permission)

                                unknown_perm = False

                                # Try to backtrace the request to MainActivity
                                path = backtrace_request(analysis, req, main_activity)

                                analyzed_req = RequestAnalysis(permission=permission, method=req.get_method(),
                                                               caller=xref, path=path)

                                if analyzed_req not in analyzed_requests:
                                    analyzed_requests.append(analyzed_req)
        #else:
        #   continue
    #
    #     # Still no match...
    #     if unknown_perm:
    #        for (ref_class, xref, offset) in req.get_xref_from():
    #            xref = xref  # type: EncodedMethod
    #
    #            # Create unknown PermRequests for other non-identifiable requests that do not belong to the SDK
    #            if not xref.get_class_name().startswith("Landroid"):
    #                # Still try to backtrace...
    #                path = backtrace_request(analysis, req, main_activity)
    #                unknown_req = RequestAnalysis(permission="Unknown Permission", method=req.get_method(),
    #                                                         reason="Could not identify requested permission:\n %s" %
    #                                                                xref.get_source(), path=path)
    #                if unknown_req not in analyzed_requests:
    #                    logging.info("Unknown permission: %s" % repr(unknown_req))
    #                    analyzed_requests.append(unknown_req)

    return analyzed_requests


def find_requests_by_string_analysis(analysis, method_analysis, analyzed_requests, permission, main_activity, visited_xrefs=[]):

    if not method_analysis:
        # may be none
        return analyzed_requests

    if method_analysis.get_method() in visited_xrefs:
        return analyzed_requests

    visited_xrefs.append(method_analysis.get_method())

    for (ref_class, xref, offset) in method_analysis.get_xref_to():

        if "requestPermission" in xref.get_name():
            path = backtrace_request(analysis, method_analysis, main_activity)

            analyzed_req = RequestAnalysis(permission=permission, method=xref,
                                           caller=method_analysis.get_method(), path=path)

            if analyzed_req not in analyzed_requests:
                return analyzed_requests + [analyzed_req]

    for (ref_class, xref, offset) in method_analysis.get_xref_to():
        analyzed_requests = find_requests_by_string_analysis(analysis, analysis.get_method_analysis(xref),
                                                             analyzed_requests, permission, main_activity,
                                                             visited_xrefs)

    return analyzed_requests


def analyze_explanations(analyzed_apk, apk, analysis):
    # type: (AnalyzedApk, APK ,Analysis) -> AnalyzedApk

    for req in analyzed_apk.analyzed_requests:
        if req.permission != "Unknown Permission":
            req.explanation = find_explanations(apk, analysis, req)

    return analyzed_apk


def run_request_analysis(analyzed_apk, apk, analysis, main_activity):
    # type: (AnalyzedApk, APK ,Analysis, str) -> AnalyzedApk

    logging.info("Starting request analysis...")
    requested_permissions = analyzed_apk.requested_permissions_from_manifest

    analyzed_apk.analyzed_requests += analyze_requests(apk, analysis, requested_permissions, main_activity)

    return analyze_explanations(analyzed_apk, apk, analysis)
