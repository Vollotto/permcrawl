import pandas as pd
import os
import json
import sys
import logging
import traceback
from datetime import datetime
from evalFormatter import format_single_analysis

sdkCount = {
    23 : 0,
    24 : 0,
    25 : 0,
    26 : 0,
    27 : 0,
    28 : 0,
}

# HTML-Template for generating basic app report
APP_TEMPLATE = \
    "<h2>%s.%s</h2>\n" \
    "<p>App %s is%sanalyzable%s</p>\n" \
    "<p>Target SDK: %d</p>\n" \
    "<p>The following permissions are requested in the App manifest: %s.</p>\n"

# HTML-Template for generating per-permission reports:
#   Name of permission
#   Requested (educated) up-front/in-context
#   Few stats
#   Detailed request analysis
#   Detailed usage analysis
# Requests and usages can be formatted by using DataFrames
PERM_TEMPLATE = \
    "<h3>%s</h3>\n" \
    "<p>Requested %s.</p>\n" \
    "<p>In all occurrences of this permission, permcrawl found %d requests and %d usages that were backtracable. " \
    "%d requests had an explanation</p>\n" \
    "<h4>requests</h4>\n" \
    "%s\n" \
    "<h4>usages</h4>\n" \
    "%s\n"


def single_html_report_from_dict(app_dict):

    logging.info("Generating HTML report for %s.%s" % (app_dict["package_name"], app_dict["app_name"]))

    # First prepare the app Template:

    not_analyzable = app_dict["target_sdk_too_low"] or app_dict["no_permission"] or app_dict["error"]

    if not_analyzable:
        reason = " due to the following reason: "

        if app_dict["error"]:
            reason += "An error occurred during analysis."
        elif app_dict["target_sdk_too_low"]:
            reason += "Target SDK is too low."
        elif app_dict["no_permission"]:
            reason += "No permissions requested."
    else:
        reason = "."

    report = APP_TEMPLATE % (app_dict["package_name"], app_dict["app_name"], app_dict["app_name"],
                             " not " if not_analyzable else " ", reason, app_dict["target_sdk"],
                             ", ".join(app_dict["declared_permissions"]))

    if not_analyzable:
        return report

    # Now we can continue with the detailed permission reports:

    for perm in app_dict["declared_permissions"]:

        location_desc = "educated " if app_dict[perm]["educated"] else "asked "
        location_desc += "up-front" if app_dict[perm]["up_front"] else (
            "in-context" if app_dict[perm]["in_context"] else "neither up-front nor in-context"
        )

        report += PERM_TEMPLATE % (perm, location_desc, app_dict[perm]["#requests_w_backtrace"],
                                   app_dict[perm]["#usages_w_backtrace"], app_dict[perm]["#requests_w_explanation"],
                                   pd.DataFrame(app_dict[perm]["requests"]).to_html(),
                                   pd.DataFrame(app_dict[perm]["usages"]).to_html())

    return report


def generate_report(app_dict, report_dir=""):
    # Returns a DataFrame containing a report overview of the analysis results
    # Optionally: Creates a HTML report of the results

    logging.info("Generating overview report for %s.%s" % (app_dict["package_name"], app_dict["app_name"]))

    # Creates and returns an overview dict for the app
    if report_dir:
        # Writes the specific app html report to the specified directory (if given)
        report_out = open("%s/%s.html" % (os.path.realpath(report_dir), app_dict["package_name"]), "w")
        report_out.write(single_html_report_from_dict(app_dict))
        # Use html link for the name
        template_key = "<a href=\"reports/%s.html\" target=\"_blank\">%s.%s</a>" % (app_dict["package_name"],
                                                                       app_dict["package_name"], app_dict["app_name"])
        report_out.close()
    else:
        template_key = app_dict["package_name"]

    # after writing the special report return a basic dict for the overall report
    template = {
        template_key: {
             "Target SDK": app_dict["target_sdk"],
             "Analyzable": not (app_dict["target_sdk_too_low"] or app_dict["no_permission"] or app_dict["error"]),
             "Declared Permissions": app_dict["declared_permissions"],
             "Permissions asked up-front": [],
             "Permissions educated up-front": [],
             "Permissions asked in-context": [],
             "Permissions educated in-context": [],
             "Non-backtracable asked permissions": [],
             "Non-backtracable educated permissions": []
        }
    }

    if template[template_key]["Analyzable"]:
        global sdkCount
        sdkCount[template[template_key]["Target SDK"]] += 1

    for perm in app_dict["declared_permissions"]:
        if app_dict[perm]["up_front"]:
            if not app_dict[perm]["educated"]:
                template[template_key]["Permissions asked up-front"] += [perm]
            else:
                template[template_key]["Permissions educated up-front"] += [perm]
        elif app_dict[perm]["in_context"]:
            if not app_dict[perm]["educated"]:
                template[template_key]["Permissions asked in-context"] += [perm]
            else:
                template[template_key]["Permissions educated in-context"] += [perm]
        else:
            if not app_dict[perm]["educated"]:
                template[template_key]["Non-backtracable asked permissions"] += [perm]
            else:
                template[template_key]["Non-backtracable educated permissions"] += [perm]

    return template


def generate_reports_from_json(indir, outdir=""):
    # Returns a DataFrame object representing the basic analysis report (overview)
    # If outdir is specified it creates HTML reports

    # Need to deactivate the linewidth limit
    pd.set_option('display.max_colwidth', -1)

    basic_reports = dict()
    analyzed_apps = 0
    analyzable_apps = 0

    for file in os.listdir(indir):
        if file.endswith(".json"):
            try:
                json_file = open(os.path.realpath(indir) + '/' + file, "r")

                app_dict = format_single_analysis(json.loads(json_file.read()))

                analyzed_apps += 1

                report = generate_report(app_dict, ((outdir + "reports/") if outdir else ""))
                del app_dict

                basic_reports.update(report)

                try:
                    d = pd.DataFrame(basic_reports, index=["Analyzable", "Target SDK", "Declared Permissions",
                                            "Permissions asked up-front", "Permissions educated up-front",
                                            "Permissions asked in-context", "Permissions educated in-context",
                                            "Non-backtracable asked permissions",
                                            "Non-backtracable educated permissions"]).T
                    x = d.to_html(escape=False)
                    del d
                    del x

                except:
                    logging.CRITICAL("Error when creating DataFrame caused by report: %s" % report)

                # Can only be a set with one element
                report_key = list(report.keys())[0]

                if report[report_key]["Analyzable"]:
                    analyzable_apps += 1

                json_file.close()

            except:
                print("Could not load %s" % file)

    # Change orientation s.t. app names form lines (and also fix the index order)
    df = pd.DataFrame(basic_reports#,index=["Analyzable", "Target SDK", "Declared Permissions",
                                            #"Permissions asked up-front", "Permissions educated up-front",
                                            #"Permissions asked in-context", "Permissions educated in-context",
                                            #"Non-backtracable asked permissions",
                                            #"Non-backtracable educated permissions"]
    ).T

    if outdir:
        with open(os.path.realpath(outdir) + "/index.html", "w") as index:
            try:
                report_html = df.to_html(escape=False)
                html = "<h1>Report from %s</h1>\n" \
                    "<p>Out of overall %d apps, %d were successfully analyzed.</p>\n" \
                    "<h2>Report Overview:</h2>\n" \
                    "%s" % (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), analyzed_apps, analyzable_apps,
                           report_html)
                index.write(html)
                return df

            except:
                (ex_type, ex_value, tb) = sys.exc_info()
                traceback.print_exception(ex_type, ex_value, tb)
                logging.error("Analyzed apps: %d" % analyzed_apps)
                logging.error("Error when writing the overall HTML Report")
    else:
        return df

if __name__ == '__main__':

    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    if len(sys.argv) > 2:
        print(generate_reports_from_json(sys.argv[1], sys.argv[2]))

        global sdkCount
        for version in sdkCount.keys():
            print("%d apps declare target SDK %d." % (sdkCount[version], version))

        exit(0)
    else:
        print("Please specify an input directory with json files and an output directory for the HTML report!")
        exit(1)
