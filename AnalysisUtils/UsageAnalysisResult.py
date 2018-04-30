from re import escape
from androguard.core.bytecodes.dvm import *
from typing import List
import json


class UsageAnalysis:

    def __init__(self, permission="Unknown Permission", method=None, path=None, analyzable=False,
                 reason="Usage not found"):

        self.permission = permission  # type: str
        self.method = method  # type: EncodedMethod
        self.path = path  # type: List[EncodedMethod]

        self.analyzable = analyzable
        if not analyzable:
            self.reason = reason
        else:
            self.reason = ""

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        return (self.permission == other.permission and
                self.method == other.method and
                self.analyzable == other.analyzable and
                self.reason == other.reason and
                self.path == other.path)

    def __ne__(self, other):
        return not self.__eq__(other)

    @classmethod
    def from_json(cls, analysis, usage_analysis_json):

        # Creates a UsageAnalysis instance from the given json dictionary
        # type: (UsageAnalysis, Analysis, dict) -> (UsageAnalysis)

        perm = usage_analysis_json["permission"]

        analyzable = usage_analysis_json["analyzable"]

        if analyzable:

            method_info = usage_analysis_json["method"]

            # Use the information in the json dict to find the methods

            ma_gen = analysis.find_methods(classname=escape(method_info["class_name"]),
                                           methodname=escape(method_info["name"]),
                                           descriptor=escape(method_info["descriptor"]),
                                           accessflags=escape(method_info["access_flags"]))
            method = None

            for ma in ma_gen:
                method = ma.get_method()

            # reconstruct the path
            path = []
            path_json = usage_analysis_json["path"]

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

            return cls(permission=perm, method=method, path=path, analyzable=analyzable)

        else:
            return cls(permission=perm, reason=usage_analysis_json["reason"].replace("\\\"", "\"").replace("\\n", "\n"))

    def __repr__(self):

        if self.analyzable:
            out = "Permission \"%s\" is used at:\n" % self.permission
            out += "%s->%s%s [access_flags = %s]\n" % (self.method.get_class_name(),
                                                       self.method.get_name(),
                                                       self.method.get_descriptor(),
                                                       self.method.get_access_flags_string())
            if not self.path:
                out += "Could not backtrace a direct callgraph to the permission request callback.\n"
            else:
                out += "Callgraph from permission request callback;\n"
                for method in self.path:
                    out += "%s->%s%s [access_flags = %s]\n" % (method.get_class_name(),
                                                               method.get_name(),
                                                               method.get_descriptor(),
                                                               method.get_access_flags_string())
        else:
            out = "Usage of permission \"%s\" could not be analyzed for the reason: \n%s" % (self.permission,
                                                                                             self.reason)

        return out

    def to_json(self, tab):

        json_out = "\t"*tab + "{\n"
        json_out += "\t"*tab + "\t\"permission\" : \"%s\",\n" % self.permission

        json_out += "\t"*tab + "\t\"analyzable\" : %s,\n" % json.dumps(self.analyzable)

        if self.analyzable:
            json_out += "\t"*tab + "\t\"method\" : {\n"
            json_out += "\t"*tab + "\t\t\"class_name\" : \"%s\",\n" % self.method.get_class_name()
            json_out += "\t"*tab + "\t\t\"name\" : \"%s\",\n" % self.method.get_name()
            json_out += "\t"*tab + "\t\t\"descriptor\" : \"%s\",\n" % self.method.get_descriptor()
            json_out += "\t"*tab + "\t\t\"access_flags\" : \"%s\"\n \t},\n" % self.method.get_access_flags_string()

            json_out += "\t"*tab + "\t\"path\" : [\n"

            if self.path:
                # need to maintain the order of the path, so we use a counter
                for i in range(0, len(self.path)):
                    json_out += "\t"*tab + "\t\t{\n"
                    json_out += "\t"*tab + "\t\t\t\"count\" : %d,\n" % i
                    json_out += "\t"*tab + "\t\t\t\"class_name\" : \"%s\",\n" % self.path[i].get_class_name()
                    json_out += "\t"*tab + "\t\t\t\"name\" : \"%s\",\n" % self.path[i].get_name()
                    json_out += "\t"*tab + "\t\t\t\"descriptor\" : \"%s\",\n" % self.path[i].get_descriptor()
                    json_out += "\t"*tab + "\t\t\t\"access_flags\" : \"%s\"\n" % self.path[i].get_access_flags_string()
                    json_out += "\t"*tab + "\t\t}"

                    if i < (len(self.path) - 1):
                        json_out += ","

                        json_out += "\n"

            json_out += "\t"*tab + "\t]\n"

        else:
            json_out += "\t"*tab + "\t\"reason\" : %s" % json.dumps(self.reason)

        json_out += "\t"*tab + "}"

        return json_out
