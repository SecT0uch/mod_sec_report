import argparse

from mod_sec_report_leoberry import output, parse_modsec_file

parser = argparse.ArgumentParser(description="ModSecurity Report generator")
parser.add_argument("logfiles",
                    metavar="LOGFILES",
                    type=str,
                    nargs="+",
                    help="ModSec log files in JSON fmt")

args = parser.parse_args()

entries = []
for logfile in args.logfiles:
    entries.extend(parse_modsec_file(logfile))

output(sorted(entries, key=lambda entry: entry["transaction"]["time_parsed"]))
