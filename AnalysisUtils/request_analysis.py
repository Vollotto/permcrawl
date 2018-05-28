from .analysis_result import AnalyzedApk
from .explanation_analysis import is_explanation
from .RequestAnalysisResult import RequestAnalysis
from androguard.core.bytecodes.dvm import *
from androguard.core.analysis.analysis import *
from typing import List
import re
import logging


def backtrace_request(analysis, request, main_activity, visited_xrefs=[]):
    # type: (Analysis, MethodClassAnalysis, str, List[MethodClassAnalysis]) -> List[EncodedMethod]
    logging.info("Searching for %s" % main_activity)

    if request in visited_xrefs:
        # this is a cycle... abort
        return []
    elif main_activity in request.get_method().get_class_name():
        # succesfully backtraced path to permission request
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
                backtrace = backtrace_request(analysis, analysis.get_method_analysis(ref_method), main_activity)

                # If the result ever is not empty we found a path
                if backtrace:
                    logging.info("Adding %s to path..." % str(request.get_method()))
                    return [request.get_method()] + backtrace

    # If not there exists no path
    return []


def find_explanation(apk, analysis, request):
    # type: (APK, Analysis, RequestAnalysis) -> str

    logging.info("Searching explanation...")
    logging.info("Searching in code...")

    # Maybe we have an explanation string directly in the code (constant, hardcoded,...)
    for str_analysis in analysis.get_strings():
        # We need the String to be used in the same method that calls our permission
        for (classobj, methodobj) in str_analysis.get_xref_from():
            # Also we need to check whether the String is really an explanation
            if methodobj == request.caller and is_explanation(str_analysis.get_value()):
                logging.info("String analysis object in requesting method: \n%s" % repr(str_analysis))
                return str_analysis.get_value()

    logging.info("Searching used string resources...")
    # Maybe there is a string ressource used as explanation
    # We can find them by searching for resource ids that are used in the method that requests the permission
    res_id = re.compile("\d{10}")
    ids_in_code = res_id.findall(request.caller.get_source())
    logging.info("Found IDs: %s" % ids_in_code)

    # Take all string resources from the APK
    str_resources = apk.get_android_resources().get_resolved_strings()[apk.get_package()]['DEFAULT']
    logging.info("Resolved Strings: %s" % str_resources)

    for id in ids_in_code:
        id = int(id)
        # Check if the id belongs to a resolved string resource
        if id in str_resources.keys():
            logging.info("Checking resolved String resource...\n%s" % str_resources[id])
            # Now check if the string is an explanation why a permission is needed
            if is_explanation(str_resources[id]):
                return str_resources[id]

    return ""


def analyze_requests(analysis, requested_permissions, main_activity):
    # type: (Analysis, List[str], str) -> List[RequestAnalysis]

    logging.info("Creating XREFs...")
    analysis.create_xref()

    # List for RequestAnalysis objects to return
    analyzed_requests = []

    # get all methods called "requestPermissions" from DalvikVMFormat object
    # TODO: How to cope with dynamic args?
    requests = analysis.find_methods(methodname="requestPermission")

    for req in requests:
        req = req  # type: MethodClassAnalysis
        logging.info("Request:\n %s" % str(req))

        if not req.get_method().get_class_name().startswith("Landroid"):
            continue

        # Get all xrefs from that are not part of the API
        for (ref_class, xref, offset) in req.get_xref_from():
            xref = xref  # type: EncodedMethod
            logging.info("XREF from: %s" % str(xref))

            if (xref.get_class_name().startswith("Landroid") or
                    xref.get_class_name().startswith("Ljava") or
                    xref.get_class_name().startswith("Lkotlin")):
                # filter requests that are part of the SDK or language
                continue

            unknown_perm = True

            for permission in requested_permissions:

                logging.info("Checking permission %s" % permission)

                if permission in xref.get_source():

                    unknown_perm = False

                    logging.info("Found permission %s\n%s" % (permission, xref.get_source()))

                    # We have found the request for the declared permission
                    # Try to backtrace the request to MainActivity
                    path = backtrace_request(analysis, req, main_activity)
                    analyzed_req = RequestAnalysis(permission=permission, method=req.get_method(),
                                                   caller=xref, path=path)
                    if analyzed_req not in analyzed_requests:
                        analyzed_requests.append(analyzed_req)

            if unknown_perm:
                # Try to relate the permission to the request via StringAnalysis

                # First, take the base class from the caller
                # Follows the scheme: Lcom/package/subpackage/class$subclass > Split at $
                base_class = xref.get_class_name().split("$")[0]

                # Now, let's try to invoke Androguard's String Analysis for all the permissions
                for permission in requested_permissions:
                    for sa in analysis.get_strings():
                        if permission in sa.get_value():
                            # found a StringAnalysis instance that seems to represent our permission
                            # so let's check the XREF set
                            for (class_analysis, method) in sa.get_xref_from():
                                # again take the base class and if we have a match treat it as positive result
                                if xref.get_class_name().split("$")[0] == base_class:
                                    logging.info("Found permission %s by base class comparison.\n" % permission)

                                    unknown_perm = False

                                    # Try to backtrace the request to MainActivity
                                    path = backtrace_request(analysis, req, main_activity)

                                    analyzed_req = RequestAnalysis(permission=permission, method=req.get_method(),
                                                                   caller=xref, path=path)

                                    if analyzed_req not in analyzed_requests:
                                        analyzed_requests.append(analyzed_req)
            # Still no match...
            if unknown_perm:
                # Create unknown PermRequests for other non-identifiable requests that do not belong to the SDK
                if not xref.get_class_name().startswith("Landroid"):
                    # Still try to backtrace...
                    path = backtrace_request(analysis, req, main_activity)
                    unknown_req = RequestAnalysis(permission="Unknown Permission", method=req.get_method(),
                                                             reason="Could not identify requested permission:\n %s" %
                                                                    xref.get_source(), path=path)
                    if unknown_req not in analyzed_requests:
                        analyzed_requests.append(unknown_req)

    return analyzed_requests

def analyze_explanations(analyzed_apk, apk, analysis):
    # type: (AnalyzedApk, APK ,Analysis) -> AnalyzedApk

    for req in analyzed_apk.analyzed_requests:
        req.explanation = find_explanation(apk, analysis, req)

    return analyzed_apk

def run_request_analysis(analyzed_apk, apk, analysis, main_activity):
    # type: (AnalyzedApk, APK ,Analysis, str) -> AnalyzedApk

    logging.info("Starting request analysis...")
    requested_permissions = analyzed_apk.requested_permissions_from_manifest

    analyzed_apk.analyzed_requests += analyze_requests(analysis, requested_permissions, main_activity)

    return analyze_explanations(analyzed_apk, apk, analysis)
