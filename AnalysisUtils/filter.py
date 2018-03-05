from AndroguardProject.androguard.androguard.core.bytecodes.apk import APK
from permcrawl import AnalyzedApk
from APIResources import load_permissions

def init_basic_infos(apk, analyzed_apk):
    apk = apk  # type: APK
    analyzedApk = analyzed_apk  # type: AnalyzedApk

    try:
        # Simply Copy Paste the Appname & Packagename
        analyzed_apk.app_name = apk.get_app_name()
        analyzed_apk.package_name = apk.get_package()
    except KeyError:
        analyzed_apk.error = True
    finally:
        return analyzed_apk

def filter_target_sdk(apk, analyzed_apk):
    apk = apk  # type: APK
    analyzed_apk = analyzed_apk  # type: AnalyzedApk

    try:
        analyzed_apk.target_sdk = int(apk.get_target_sdk_version())

        # Target SDK version should be greater than 23 (Marshmallow)
        # since Marshmallow introduced dynamic permission requests
        if analyzed_apk.target_sdk > 23:
            analyzed_apk.target_sdk_too_low = False
    except KeyError:
        analyzed_apk.error = True
    finally:
        return analyzed_apk

def filter_manifest_permission_requests(apk, analyzed_apk):
    apk = apk  # type: APK
    analyzed_apk = analyzed_apk  # type: AnalyzedApk

    # initialize dictionary for permissions
    perms = load_permissions(analyzed_apk.target_sdk)

    # list for permissions requested in manifest
    requested_permissions = []

    try:
        for requested_permission in apk.get_permissions():
            # only consider permissions that are aosp permissions...
            if requested_permission in perms.keys():
                # ... and which are classified as "dangerous"
                if perms[requested_permission]["protectionLevel"] == "dangerous":
                    requested_permissions.append(requested_permission)

        if requested_permissions:
            analyzed_apk.no_permission_declared = False
        analyzed_apk.requested_permissions_from_manifest.append(requested_permissions)

    except KeyError:
        analyzed_apk.error = True

    finally:
        return analyzed_apk