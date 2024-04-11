import argparse

import mod_sec_report_leoberry

parser = argparse.ArgumentParser(description="ModSecurity Report generator")
parser.add_argument("logfiles",
                    metavar="LOGFILES",
                    type=str,
                    nargs="+",
                    help="ModSec log files in JSON fmt")

args = parser.parse_args()

entries = []
for logfile in args.logfiles:
    entries.extend(mod_sec_report_leoberry.parse_modsec_file(logfile))

mod_sec_report_leoberry.output(sorted(entries, key=lambda entry: entry["transaction"]["time_parsed"]))
