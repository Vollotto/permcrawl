import logging
from .analysis_result import AnalyzedApk
from androguard.core.bytecodes.apk import APK
from androguard.core.api_specific_resources import load_permissions


def init_basic_infos(apk, analyzed_apk):
    # type: (APK, AnalyzedApk) -> AnalyzedApk

    logging.info("Extracting basic app information...")

    try:
        # Simply Copy Paste the Appname & Packagename
        analyzed_apk.app_name = apk.get_app_name()
        logging.info("App Name: %s" % apk.get_app_name())

        analyzed_apk.package_name = apk.get_package()
        logging.info("Package Name: %s" % apk.get_package())
    except KeyError:
        logging.error("Key Error during extraction of basic app information!")
        analyzed_apk.error = True
    finally:
        return analyzed_apk


def filter_target_sdk(apk, analyzed_apk):
    # type: (APK, AnalyzedApk) -> AnalyzedApk

    try:
        analyzed_apk.target_sdk = int(apk.get_effective_target_sdk_version())
        logging.info("Target SDK version: %d" % int(apk.get_effective_target_sdk_version()))

        # Target SDK version should be greater than 23 (Marshmallow)
        # since Marshmallow introduced dynamic permission requests
        if analyzed_apk.target_sdk > 23:
            if analyzed_apk.target_sdk > 25:
                analyzed_apk.target_sdk = 25
            analyzed_apk.target_sdk_too_low = False
        else:
            logging.warning("Illegal target SDK version")
    except KeyError:
        logging.error("Key Error during extraction of target SDK version!")
        analyzed_apk.error = True
    finally:
        return analyzed_apk


def filter_manifest_permission_requests(apk, analyzed_apk):
    # type: (APK, AnalyzedApk) -> AnalyzedApk

    # initialize dictionary for permissions
    logging.info("Loading dictionary for permissions...")
    perms = load_permissions(analyzed_apk.target_sdk)

    # list for permissions requested in manifest
    requested_permissions = []

    try:
        for requested_permission in apk.get_permissions():
            # only consider permissions that are aosp permissions...
            if requested_permission in perms.keys():
                # ... and which are classified as "dangerous"
                if perms[requested_permission]["protectionLevel"] == "dangerous":
                    logging.info("%s uses permission %s." % (analyzed_apk.app_name, requested_permission))
                    requested_permissions.append(requested_permission)

        if requested_permissions:
            analyzed_apk.no_permission_declared = False
        else:
            logging.warning("%s requests no permissions in its manifest!" % analyzed_apk.app_name)

        analyzed_apk.requested_permissions_from_manifest = requested_permissions

    except KeyError:
        logging.error("Key Error during extraction of requested permissions!")
        analyzed_apk.error = True

    finally:
        return analyzed_apk
