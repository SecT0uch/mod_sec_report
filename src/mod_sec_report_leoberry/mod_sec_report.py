#!/usr/bin/env python3

import datetime
import gzip
import json
import sys

from jinja2 import Environment, FileSystemLoader


def parse_modsec_line(line):
    """
    Parse a single line from a mod_security log file in JSON format.
    """
    entry = json.loads(line)

    transaction_dt = entry["transaction"]["time_stamp"]
    entry["transaction"]["time_parsed"] = datetime.datetime.strptime(transaction_dt, "%a %b %d %H:%M:%S %Y")

    if "body" in entry["transaction"]["request"] and len(entry["transaction"]["request"]["body"]) > 0:
        entry["request"]["body"] = [entry["transaction"]["request"]["body"][0].encode("ascii", errors="ignore").decode("utf8")]

    if len(entry["transaction"]["messages"]) > 0:
      entry["errors"] = []
      for message in entry["transaction"]["messages"]:
        entry["errors"] = message["message"]

    return entry


def parse_modsec_file(path):
    parsed_log_lines = []

    if path.endswith(".gz"):
        fh = gzip.open(path, "rt", errors="replace", encoding="utf-8")
    else:
        fh = open(path, "r", errors="replace", encoding="utf-8")

    line_cnt = 0
    for line in fh:
        line_cnt += 1
        try:
            parsed_log_lines.append(parse_modsec_line(line))
        except Exception as err:
            sys.stderr.write("Couldn't parse line {} of {}. Skipping. Error = {}\n".format(line_cnt, path, err))

    fh.close()

    return parsed_log_lines


def output(entries):
    environment = Environment(loader=FileSystemLoader("templates/"))
    template = environment.get_template("mod_sec_report.tpl")
    print(template.render(entries=entries))
