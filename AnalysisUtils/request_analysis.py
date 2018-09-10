import logging
import re
from typing import List

from androguard.core.analysis.analysis import *
from androguard.core.bytecodes.dvm import *

from .RequestAnalysisResult import RequestAnalysis
from .analysis_result import AnalyzedApk
from .ExplanationAnalysis.explanation_analysis import is_explanation


def backtrace_request(analysis, request, main_activities, visited_xrefs=[]):
    """
    Tries to backtrace the given permission request to a main activity
    :param analysis: Androguards Analysis instance
    :param request: The MethodClassAnalysis instance of the request
    :param main_activities: The declared main activities of the app
    :param visited_xrefs: All XREFs from that have already been visited during backtracing
    :return: The path from the request to a main activity
    """
    # type: (Analysis, MethodClassAnalysis, List[str], List[MethodClassAnalysis]) -> List[EncodedMethod]
    logging.debug("Searching for %s" % ";".join(main_activities))

    if request in visited_xrefs:
        # this is a cycle... abort
        return []
    else:
        for main_activity in main_activities:
            if main_activity in request.get_method().get_class_name():
                # successfully backtraced path to permission request
                logging.info("Found MainActivity")
                return [request.get_method()]

        # Add the current usage to the xrefs already visited (empty list on first call by default)
        visited_xrefs += [request]

        # If we do not have xrefs from this path won't lead to any result
        if not request.get_xref_from():
            return []
        else:
            # Backtrace all XREFs from
            for (ref_class, ref_method, offset) in request.get_xref_from():
                # Recursively call the backtracing method but now with the XREF from as "request"
                backtrace = backtrace_request(analysis, analysis.get_method_analysis(ref_method),
                                              main_activities, visited_xrefs)

                # If the result ever is not empty we found a path
                if backtrace:
                    logging.debug("Adding %s to path..." % str(request.get_method()))
                    return [request.get_method()] + backtrace

    # If not there exists no path
    return []


def find_explanations(apk, analysis, request):
    """
    Filters explanation candidates for the given request
    :param apk: The result of the whole analysis
    :param analysis: Androguards Analysis instance
    :param request: An analyzed permission request as instance of :class:`~RequestAnalysisResult.RequestAnalysis`
    :return: A list of explanations
    """
    # type: (APK, Analysis, RequestAnalysis) -> List[str]

    logging.debug("Searching possible explanations...")
    logging.debug("Searching in code...")

    explanations = []

    # Maybe we have an explanation string directly in the code (constant, hardcoded,...)
    for str_analysis in analysis.get_strings():
        # We need the Strings used in the same method that calls our permission
        for (classobj, methodobj) in str_analysis.get_xref_from():
            # Also we need to check whether the String is really an explanation
            if methodobj == request.caller and is_explanation(request.permission, str_analysis.get_value()):
                logging.info("String analysis object in requesting method: \n%s" % repr(str_analysis))
                explanations.append(str_analysis.get_value())

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
                explanations.append(str_resources[str_id])

    return explanations


def analyze_requests(apk, analysis, requested_permissions, main_activities):
    """
    Extracts all identifyable permission requests and their surrounding context (caller of requestPermissions, explanation, backtrace to main activity) from the given apk file
    :param apk: Androguard's APK instance (for future versions maybe needed)
    :param analysis: Androguard's analysis instance
    :param requested_permissions: Extracted AOSP permissions from manifest that are requested by the app to analyze
    :param main_activities: Declared main activities of the app
    :return: a list of :class:`~RequestAnalysisResult.RequestAnalysis` that represent the single analyzed requests
    """
    # type: (APK, Analysis, List[str], List[str]) -> List[RequestAnalysis]

    # Initialize the Analysis instance
    logging.info("Creating XREFs...")
    analysis.create_xref()

    # List for RequestAnalysis objects to return
    analyzed_requests = []

    ### STRING ANALYSIS ###
    # first try to use Androguards' StringAnalysis
    for analyzed_string in analysis.get_strings():
        # check for all StringAnalysis objects whether the value equals a permission string
        if analyzed_string.get_value() in requested_permissions:
            # If so this may be used in a request -> take further steps
            for (class_analysis, method) in analyzed_string.get_xref_from():
                analyzed_requests = find_requests_by_string_analysis(analysis, analysis.get_method_analysis(method),
                                                                     analyzed_requests, analyzed_string.get_value(),
                                                                     main_activities)

    ### SEARCHING DECOMPILED CALLER ###
    # get all methods called "requestPermissions" from Androguard Analysis
    requests = analysis.find_methods(methodname="requestPermission")

    for req in requests:
        req = req  # type: MethodClassAnalysis
        logging.debug("Request:\n %s" % str(req))

        # Check all XREFs from of the actual request
        for (ref_class, xref, offset) in req.get_xref_from():
            xref = xref  # type: EncodedMethod
            logging.debug("XREF from: %s" % str(xref))

            if (xref.get_class_name().startswith("Landroid") or
                    xref.get_class_name().startswith("Ljava") or
                    xref.get_class_name().startswith("Lkotlin")):
                # filter requests that are part of the SDK or language
                continue

            # Now check for each permission requested in the Manifest whether it occurs in the decompiled source code
            for permission in requested_permissions:

                logging.debug("Checking permission %s" % permission)

                if permission in xref.get_source():
                    logging.debug("Found permission %s\n%s" % (permission, xref.get_source()))

                    # We have found the request for the declared permission
                    # Try to backtrace the request to MainActivity
                    path = backtrace_request(analysis, req, main_activities)
                    analyzed_req = RequestAnalysis(permission=permission, method=req.get_method(),
                                                   caller=xref, path=path)
                    if analyzed_req not in analyzed_requests:
                        # We do not want duplicates in the list to return, maybe another approach already found this one
                        analyzed_requests.append(analyzed_req)

        ### BASE CLASS COMPARISON ###
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

                                # Try to backtrace the request to MainActivity
                                path = backtrace_request(analysis, req, main_activities)

                                analyzed_req = RequestAnalysis(permission=permission, method=req.get_method(),
                                                               caller=xref, path=path)

                                if analyzed_req not in analyzed_requests:
                                    # Again, no duplicates
                                    analyzed_requests.append(analyzed_req)
    return analyzed_requests


def find_requests_by_string_analysis(analysis, method_analysis, analyzed_requests, permission, main_activities,
                                     visited_xrefs=[]):
    """
    Called when a permission string has been found by using Androguard's StringAnalysis, tries to find the request by
    following the XREFs of this string
    :param analysis: Androguard's analysis instance
    :param method_analysis: MethodClassAnalysis instance of the XREF that should be checked in this iteration;
                            on first call this is a method from where the String is referenced
    :param analyzed_requests:  a list of :class:`~RequestAnalysisResult.RequestAnalysis` that represent the single
                                analyzed requests which already have been found
    :param permission: The permission represented by the found String
    :param main_activities: The main activities declared in the Manifest of the app
    :param visited_xrefs: The XREFs that already have been vissited
    :return: The refreshed list of analyzed requests
    """
    if not method_analysis:
        # may be none in the case that the string is referenced nowhere within the code
        return analyzed_requests

    if method_analysis.get_method() in visited_xrefs:
        # We already checked this method -> cycle -> abort
        return analyzed_requests

    # Make sure that this method is not visited anymore
    visited_xrefs.append(method_analysis.get_method())

    # On first call method_analysis is one of the methods from where the permission string is referenced
    # -> follow all possible paths starting from this method until we find a request
    for (ref_class, xref, offset) in method_analysis.get_xref_to():

        if "requestPermission" in xref.get_name():
            # We found a request in the path, so let's try to backtrace it to a main activity
            path = backtrace_request(analysis, method_analysis, main_activities)

            analyzed_req = RequestAnalysis(permission=permission, method=xref,
                                           caller=method_analysis.get_method(), path=path)

            if analyzed_req not in analyzed_requests:
                # Make sure that we did not already find this request and that the list contains no duplicates
                return analyzed_requests + [analyzed_req]

    # There may exists other requests in another path starting from the string reference so we do not abort after
    # finding one of them -> recursively go down further and only abort in case of a cycle
    for (ref_class, xref, offset) in method_analysis.get_xref_to():
        analyzed_requests = find_requests_by_string_analysis(analysis, analysis.get_method_analysis(xref),
                                                             analyzed_requests, permission, main_activities,
                                                             visited_xrefs)

    return analyzed_requests


def analyze_explanations(analyzed_apk, apk, analysis):
    """
    Executes the explanation analysis for each identified request
    :param analyzed_apk: The result of the whole analysis as instance of :class:`~analysis_result.AnalyzedApk`
    :param apk: Androguard's APK instance needed for explanation analysis
    :param analysis: Androguard's analysis instance
    :return: The result of the analysis now containing explanations
    """
    # type: (AnalyzedApk, APK ,Analysis) -> AnalyzedApk

    # For all requests except for unknown ones (deprecated functionality used during testing) try to find explanations
    for req in analyzed_apk.analyzed_requests:
        if req.permission != "Unknown Permission":
            req.explanation = find_explanations(apk, analysis, req)

    return analyzed_apk


def run_request_analysis(analyzed_apk, apk, analysis, main_activities):
    """
    Executes the necessary steps for all requests:
        1. Extracting the requested permissions from the manifest
        2. Finding the request and identifying the requested permission
        3. Identifying explanations if used
    :param analyzed_apk: The result of the whole analysis as instance of :class:`~analysis_result.AnalyzedApk`
    :param apk: Androguard's APK instance needed for explanation analysis
    :param analysis: Androguard's analysis instance
    :param main_activities: The declared main activities of the app
    :return: The result of the analysis now initialized with all analyzed requests
    """
    # type: (AnalyzedApk, APK ,Analysis, str) -> AnalyzedApk

    logging.info("Starting request analysis...")

    # Extract dangerous AOSP permissions from manifest
    requested_permissions = analyzed_apk.requested_permissions_from_manifest

    # Execute actual request analysis
    analyzed_apk.analyzed_requests += analyze_requests(apk, analysis, requested_permissions, main_activities)

    # Complete analysis with explanations
    return analyze_explanations(analyzed_apk, apk, analysis)
