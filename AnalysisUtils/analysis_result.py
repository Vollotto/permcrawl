import json
from .RequestAnalysisResult import RequestAnalysis
from .UsageAnalysisResult import UsageAnalysis


class AnalyzedApk:
    '''
        Represents an App which has been analyzed for permission requests and their usages
    '''

    def __init__(self):

        self.app_name = ""
        self.package_name = ""

        # Path to APK on disk
        self.apk_path = ""

        # Defaults make app not analyzable
        self.target_sdk = 0
        self.target_sdk_too_low = True
        self.no_permission_declared = True
        # Only Error is set to false by default since submodules set it to true if they face an error
        self.error = False

        self.requested_permissions_from_manifest = []

        self.analyzed_requests = []
        self.analyzed_usages = []

    @classmethod
    def from_json(cls, analysis, json_dict):
        # Creates a AnalyzedApk instance from the given json dictionary
        # type: (AnalyzedApk, Analysis, dict) -> (AnalyzedApk)

        apk = cls()

        apk.app_name = json_dict["app_name"]
        apk.package_name = json_dict["package_name"]
        apk.apk_path = json_dict["apk_path"]
        apk.target_sdk = json_dict["target_sdk"]

        apk.target_sdk_too_low = json_dict["target_sdk_too_low"]
        apk.no_permission_declared = json_dict["no_permission"]
        apk.error = json_dict["error"]

        for perm in json_dict["permissions_from_manifest"]:
            apk.requested_permissions_from_manifest.append(perm)

        for req_dict in json_dict["analyzed_requests"]:
            apk.analyzed_requests.append(RequestAnalysis.from_json(analysis, req_dict))

        for usage_dict in json_dict["analyzed_usages"]:
            apk.analyzed_usages.append(UsageAnalysis.from_json(analysis, usage_dict))

        return apk

    def is_analyzable(self):
        return not (self.target_sdk_too_low or self.no_permission_declared or self.error)

    def __repr__(self):
        if self.is_analyzable():
            out = "App %s:%s is analyzable\n" % (self.package_name, self.app_name)

            out += "%s targets SDK Level %d\n" % (self.app_name, self.target_sdk)

            out += "%s requests the following permissions:\n" % self.app_name

            for perm in self.requested_permissions_from_manifest:
                out += "%s\n" % perm

            out += "##### DETAILED ANALYSIS#####\n"

            for req in self.analyzed_requests:
                out += repr(req)

            for usage in self.analyzed_usages:
                out += repr(usage)
        else:
            out = "App %s:%s is not analyzable due to the following reason(s):\n" % (self.package_name, self.app_name)

            if self.target_sdk_too_low:
                out += "%s targets SDK Level %d (too low for dynamic runtime permission requests)\n" \
                            % (self.app_name, self.target_sdk)
            if self.no_permission_declared:
                out += "%s requests no permissions\n" % self.app_name
            if self.error:
                out += "Androguard ran into an internal error during APK analysis"

        return out

    def to_json(self):
        json_out = "{\n"

        json_out += "\t\"app_name\" : \"%s\",\n" % self.app_name
        json_out += "\t\"package_name\" : \"%s\",\n" % self.package_name
        json_out += "\t\"apk_path\" : \"%s\",\n" % self.apk_path
        json_out += "\t\"target_sdk\" : %d,\n" % self.target_sdk

        json_out += "\t\"target_sdk_too_low\" : %s,\n" % json.dumps(self.target_sdk_too_low)
        json_out += "\t\"no_permission\" : %s,\n" % json.dumps(self.no_permission_declared)
        json_out += "\t\"error\" : %s,\n" % json.dumps(self.error)

        json_out += "\t\"permissions_from_manifest\" : [\n"

        for i in range(0, len(self.requested_permissions_from_manifest)):
            json_out += "\t\t\"%s\"" % self.requested_permissions_from_manifest[i]

            if i < len(self.requested_permissions_from_manifest) - 1:
                json_out += ","
            json_out += "\n"

        json_out += "\t],\n"

        json_out += "\t\"analyzed_requests\" : [\n"

        for i in range(0, len(self.analyzed_requests)):
            json_out += self.analyzed_requests[i].to_json(2)

            if i < len(self.analyzed_requests) - 1:
                json_out += ","
            json_out += "\n"

        json_out += "\t],\n"

        json_out += "\t\"analyzed_usages\" : [\n"

        for i in range(0, len(self.analyzed_usages)):
            json_out += self.analyzed_usages[i].to_json(2)

            if i < len(self.analyzed_usages) - 1:
                json_out += ","
            json_out += "\n"

        json_out += "\t]\n"

        json_out += "}"

        return json_out
