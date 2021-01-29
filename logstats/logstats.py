#!/usr/bin/python3
"""Logfile statistics."""
import argparse
import collections
import enum
import resource


# Minimum of fields we expect from a valid log line
MIN_REC_NO = 4


class Severities(enum.Enum):
    """Log message severities."""

    INFO = 1
    DEBUG = 2
    WARNING = 3
    ERROR = 4


def cleaner(input, datastore):
    """Yield input lines we consider log messages from units.

    Will take an iterator of complete log lines and yield log message records,
    dropping records that are shorter than the expected length and which
    do not start with 'unit-'

    :param input: iterator
    :return: yields log records from units
    """
    for line in input:
        record = line.split(maxsplit=MIN_REC_NO - 1)
        if len(record) < MIN_REC_NO:
            datastore.dropped_cnt += 1
            continue
        unit_field = record[0].split("-")
        if len(unit_field) >= 3 and unit_field[0] == "unit":
            charm = "-".join(unit_field[1:-1])  # chop of leading unit and trailing num
            yield charm, record[2], record[3].strip()
        else:
            datastore.dropped_cnt += 1


def get_sev(sev_str):
    """Return severity enum for a string, or None if unfound."""
    try:
        sev = Severities[sev_str]
    except KeyError:
        # invalid log message severity, ignoring log record
        return
    return sev


def analyze(records, datastore, charm_filter=None):
    """Analyze log records.

    Build up our stats from an iterator of log records

    :param records: log record iterator
    :param datastore: datastore object to save stats in
    :param charm_filter: optional: only parse log messages from given charm
    :return:
    """
    for charm, sev_str, msg in records:
        if charm_filter and charm != charm_filter:
            continue
        sev = get_sev(sev_str)
        if sev is not None:
            datastore.charm_severity_cnt[charm][sev] += 1
            datastore.message_cnt[msg, sev] += 1


def calc_log_stats(args, datastore):
    """Analyze a logfile, populate datastore."""
    with open(args.logfile) as f:
        analyze(cleaner(f, datastore), datastore, args.charm_filter)


def print_report(datastore):
    """Print a report of the collected statistics."""
    overall_messages = 0
    warning_charms = [
        k for k, v in datastore.charm_severity_cnt.items() if Severities.WARNING in v
    ]
    print("Charms that produced warning messages: ", ", ".join(warning_charms))
    severity_cnt = collections.defaultdict(int)
    for sev_dict in datastore.charm_severity_cnt.values():
        for sev, cnt in sev_dict.items():
            severity_cnt[sev] += cnt
    print("Severity counts: ")
    for sev, cnt in severity_cnt.items():
        print("  {}: {}".format(sev.name, cnt))
    print("Duplicate messages:")
    for msg_sev, cnt in datastore.message_cnt.items():
        if cnt < 2:  # not a duplicate
            continue
        print("  {}: {} -- '{}'".format(msg_sev[1].name, cnt, msg_sev[0]))
    print("Message severity ratios per charm:")
    for charm, sev_dict in datastore.charm_severity_cnt.items():
        print("  {}".format(charm))
        charm_total = sum([cnt for cnt in sev_dict.values()])
        overall_messages += charm_total
        print("    Total messages: {}".format(charm_total))
        for sev, cnt in sev_dict.items():
            print("    {}: {:.2%}".format(sev.name, cnt / charm_total))
    print("Total analyzed log messages:", overall_messages)
    print("Dropped log messages:", datastore.dropped_cnt)


def parse_args():
    """Parse commandline args."""
    parser = argparse.ArgumentParser(description="Log parser")
    parser.add_argument(
        "-c", "--charm-filter", help="only report on log messages from this charm"
    )
    parser.add_argument("logfile", help="Log file to analyze")
    parsed_args = parser.parse_args()
    return parsed_args


if __name__ == "__main__":
    args = parse_args()
    # Set up datastore structure
    datastore = collections.namedtuple(
        "logstats", ["charm_severity_cnt", "message_cnt", "dropped_cnt"]
    )
    datastore.charm_severity_cnt = collections.defaultdict(
        lambda: collections.defaultdict(int)
    )
    datastore.message_cnt = collections.Counter()
    datastore.dropped_cnt = 0
    calc_log_stats(args, datastore)
    print_report(datastore)
    print("Memory usage: %s (kb)" % resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
