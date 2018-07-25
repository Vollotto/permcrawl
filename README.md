# permcrawl

Permcrawl is able to analyze APK files for permission requests and their corresponding usages

Prerequisites:

androguard needs to be installed
for logs a "log" directory must exist in the base directory
for json files an "out" directory must exist in the base directory
for html reports the directory structure <some_out_directory>/reports/ must exist

Usage:
python3 permcrawl.py -apk /path/to/apk-file-to-analyze
-j generates a json report in the out directory
-p prints the results
-i/-d sets log level to info/debug (-d is not recommended)
-l activates logging to a file

For easy evaluation there is a report generating script HtmlReport.py in ./AnalysisUtils/EvalUtils that evaluates json results and creates an Html overall report and detailed reports for the single apks.
Usage python3 ./AnalysisUtils/EvalUtils/HtmlReport.py <indir> <outdir>
indir is a mandatory argument that specifies a directory with permcrawl json output files
outdir is a mandatory argument that specifies a directory where the HTML reports should be created, which must have the structure explained above

For larger datasets, GNU parallel is recommended
