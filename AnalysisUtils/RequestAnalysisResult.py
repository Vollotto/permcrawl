import json
from re import escape


class RequestAnalysis:

    def __init__(self, permission, method, path, caller=None, reason=""):
        """
        Creates a RequestAnalysis instance from the given permission, callee and caller

        :param permission: The string representation of the requested permission
        :param method: the method that requests the permission (one alternative of the several "requestPermissions"
                        methods
        :param path: The backtraced path to a main activity if available
        :param caller: The method that calls "requestPermissions"
        :param reason: Log message for unidentifyable requests (testing only)
        """
        # type: (str, EncodedMethod, EncodedMethod) -> ()

        self.permission = permission
        self.method = method

        self.caller = caller

        self.reason = reason

        self.path = path

        # List of identified explanations if available
        self.explanation = []

        return

    def __eq__(self, other):
        """
        Equality check needed to avoid duplicates
        :param other:
        :return:
        """
        if not isinstance(other, self.__class__):
            return False
        return (self.permission == other.permission and
                self.method == other.method and
                self.caller == other.caller and
                self.reason == other.reason and
                self.path == other.path and
                self.explanation == other.explanation)

    def __ne__(self, other):
        return not self.__eq__(other)

    @classmethod
    def from_json(cls, analysis, req_analysis_json):
        """
        Creates a RequestAnalysis instance from the given json dictionary
        Note that this method only was used for testing reasons and that the EvalUtils work directly with JSON
        representations
        :param analysis: Androguard Analysis instance of the app to analyze
        :param req_analysis_json: The JSON representation of a RequestAnalysis
        :return: An fully initialized RequestAnalysis instance
        """
        # type: (RequestAnalysis, Analysis, dict) -> (RequestAnalysis)

        perm = req_analysis_json["permission"]

        # Use the information in the json dict to find the methods
        # Load the ContentProvider map according to the (shadow) target SDK

        ma_gen = analysis.find_methods(classname=escape(req_analysis_json["method"]["class_name"]),
                                       methodname=escape(req_analysis_json["method"]["name"]),
                                       descriptor=escape(req_analysis_json["method"]["descriptor"]),
                                       accessflags=escape(req_analysis_json["method"]["access_flags"]))

        # Since we give all information our result must be unique
        # -> only 1 item from generator
        method = None
        for ma in ma_gen:
            method = ma.get_method()

        caller = ""
        reason = ""

        if not "Unknown Permission" == perm:

            ma_gen = analysis.find_methods(classname=escape(req_analysis_json["caller"]["class_name"]),
                                           methodname=escape(req_analysis_json["caller"]["name"]),
                                           descriptor=escape(req_analysis_json["caller"]["descriptor"]),
                                           accessflags=escape(req_analysis_json["caller"]["access_flags"]))

            for ma in ma_gen:
                caller = ma.get_method()

        else:
            reason = req_analysis_json["reason"].replace("\\\"", "\"").replace("\\n", "\n")

        # reconstruct the path
        path = []
        path_json = req_analysis_json["path"]

        if path_json:
            for method_info in path_json:
                # Init a list of the needed size
                path.append(None)

            for method_info in path_json:

                # Use the information in the json dict to find the methods

                ma_gen = analysis.find_methods(classname=escape(method_info["class_name"]),
                                               methodname=escape(method_info["name"]),
                                               descriptor=escape(method_info["descriptor"]),
                                               accessflags=escape(method_info["access_flags"]))

                # Since we give all information our result must be unique
                # -> only 1 item from generator
                for ma in ma_gen:
                    node = ma.get_method()
                    # use the count value to keep track of the order
                    path[method_info["count"]] = node

        req = cls(permission=perm, method=method, caller=caller, reason=reason, path=path)

        req.explanation = json.loads(req_analysis_json["explanation"])

        return req

    def __repr__(self):
        """

        :return: A formatted basic string representation of this permission request
        """
        out = "Permission %s requested at:\n" % self.permission
        out += "%s->%s%s [access_flags = %s]\n" % (self.method.get_class_name(),
                                                   self.method.get_name(),
                                                   self.method.get_descriptor(),
                                                   self.method.get_access_flags_string())
        if self.caller:
            out += "Called from:\n"
            out += "%s->%s%s [access_flags = %s]\n" % (self.caller.get_class_name(),
                                                       self.caller.get_name(),
                                                       self.caller.get_descriptor(),
                                                       self.caller.get_access_flags_string())
        else:
            out += "Not analyzable for the reason:\n %s" % self.reason

        if self.path:
            out += "Callgraph from MainActivity:\n"
            for method in self.path:
                out += "%s->%s%s [access_flags = %s]\n" % (method.get_class_name(),
                                                           method.get_name(),
                                                           method.get_descriptor(),
                                                           method.get_access_flags_string())
        else:
            out += "Could not backtrace the permission request to MainActivity.\n"

        if self.explanation:
            out += "Found explanation for the permission request:\n%s\n" % self.explanation
        else:
            out += "No explanation for the permission request found.\n"

        return out

    def to_json(self, tab):
        """
        Creates a json representation of this permission request to persist analysis results
        :param tab: For better readability of the created JSON files this int can be used to prepend a number of TABs
        :return:
        """
        # Tab parameter simply for formatting
        # Output is formatted for optimal readability
        json_out = "\t"*tab + "{\n"
        json_out += "\t"*tab + "\t\"permission\" : \"%s\" ,\n" % self.permission

        json_out += "\t"*tab + "\t\"method\" : {\n"
        json_out += "\t"*tab + "\t\t\"class_name\" : \"%s\",\n" % self.method.get_class_name()
        json_out += "\t"*tab + "\t\t\"name\" : \"%s\",\n" % self.method.get_name()
        json_out += "\t"*tab + "\t\t\"descriptor\" : \"%s\",\n" % self.method.get_descriptor()
        json_out += "\t"*tab + "\t\t\"access_flags\" : \"%s\"},\n" % self.method.get_access_flags_string()

        if self.caller:
            json_out += "\t" * tab + "\t\"caller\" : {\n"
            json_out += "\t" * tab + "\t\t\"class_name\" : \"%s\",\n" % self.caller.get_class_name()
            json_out += "\t" * tab + "\t\t\"name\" : \"%s\",\n" % self.caller.get_name()
            json_out += "\t" * tab + "\t\t\"descriptor\" : \"%s\",\n" % self.caller.get_descriptor()
            json_out += "\t" * tab + "\t\t\"access_flags\" : \"%s\" },\n" % self.caller.get_access_flags_string()

        else:
            json_out += "\t" * tab + "\t\"reason:\" : %s,\n" % json.dumps(self.reason)

        json_out += "\t" * tab + "\t\"path\" : [\n"

        if self.path:
            # need to maintain the order of the path, so we use a counter
            for i in range(0, len(self.path)):
                json_out += "\t" * tab + "\t\t{\n"
                json_out += "\t" * tab + "\t\t\t\"count\" : %d,\n" % i
                json_out += "\t" * tab + "\t\t\t\"class_name\" : \"%s\",\n" % self.path[i].get_class_name()
                json_out += "\t" * tab + "\t\t\t\"name\" : \"%s\",\n" % self.path[i].get_name()
                json_out += "\t" * tab + "\t\t\t\"descriptor\" : \"%s\",\n" % self.path[i].get_descriptor()
                json_out += "\t" * tab + "\t\t\t\"access_flags\" : \"%s\"\n" % self.path[i].get_access_flags_string()
                json_out += "\t" * tab + "\t\t}"

                if i < (len(self.path) - 1):
                    json_out += ","

                    json_out += "\n"

        json_out += "\t" * tab + "\t],\n"

        # Finally append the explanation
        json_out += "\t" * tab + "\t\"explanation\" : %s" % json.dumps(self.explanation)

        json_out += "\t" * tab + "}"

        return json_out
