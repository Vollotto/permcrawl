import argparse
import zipfile
from AnalysisUtils.AndroguardProject.androguardStarter import invoke_androguard
from AnalysisUtils.filter import *
from AnalysisUtils.request_analysis import *
from AnalysisUtils.usage_analysis import *
from AnalysisUtils.analysis_result import AnalyzedApk
from androguard.core.analysis.analysis import Analysis


def analyze(path_to_apk):

    logging.info("Starting analysis...")

    app_to_analyze = AnalyzedApk()

    try:
        a, d, dx = invoke_androguard(path_to_apk)
    except zipfile.BadZipFile:
        app_to_analyze.error = True
        return app_to_analyze

    app_to_analyze = init_basic_infos(a, app_to_analyze)

    app_to_analyze = filter_target_sdk(a, app_to_analyze)

    app_to_analyze = filter_manifest_permission_requests(a, app_to_analyze)

    if app_to_analyze.error:
        logging.critical("Error during extraction of basic infos, maybe the app is obfuscated!")
        exit(42)

    if not app_to_analyze.is_analyzable():
        logging.error("App is not analyzable, skipping request and usage analysis")
        return app_to_analyze

    # Prepare analysis instance
    analysis = Analysis()

    for vm in d:
        analysis.add(vm)

    logging.info("Creating XREFs...")
    analysis.create_xref()

    app_to_analyze = run_request_analysis(app_to_analyze, a, analysis, a.get_main_activity().replace(".","/"))

    try:
        app_to_analyze = run_usage_analysis(app_to_analyze, analysis)
    except Exception as e:
        logging.critical("Exception during UsageAnalysis:\n%s" % str(e))
        exit(43)

    logging.info("Finished analysis...")

    return app_to_analyze


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="Test permission analysis")

    parser.add_argument("-apk", "--input",
                        required=True, help="Path to apk file")

    parser.add_argument("-p", "--print",
                        action='store_true', help="Activate printing the analysis result to stdout")

    parser.add_argument("-d", "--debug",
                        action='store_true', help='Activate debug messages')

    parser.add_argument("-i", "--info",
                        action='store_true', help='Activate info messages')

    parser.add_argument("-j", "--json",
                        action='store_true', help='Export the collected data into json format')

    args = parser.parse_args()

    logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')

    logger = logging.getLogger()

    if args.debug:
        logger.setLevel(logging.DEBUG)
    elif args.info:
        logger.setLevel(logging.INFO)

    apk = analyze(args.input)
    apk.apk_path = args.input

    if args.print:
        print(repr(apk))

    if args.json:
        try:
            outname = os.path.dirname(os.path.realpath(sys.argv[0])) \
                      + "/out/" \
                      + apk.package_name.replace(".", "_").replace("\s","_")\
                      + "." \
                      + apk.app_name.replace("\s","_")\
                      + ".json"

            with open(outname, "w") as out:
                out.write(apk.to_json())
        except IOError:
            logging.critical("Error when writing to json file!")
            exit(44)

    exit(0)
