#!/usr/bin/env python
# coding: utf-8
#

# natives
import os
import sys
import sys
import json
import time
import traceback
from datetime import datetime


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))


# third parties
import splunk
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration
from splunklib import client
from stix_shifter.stix_translation import stix_translation
from stix2.utils import format_datetime, get_timestamp, parse_into_datetime, STIXdatetime

# internals
from utils import setup_logging


class ConversionError(Exception):
    pass


@Configuration()
class STIXToSplunkCommand(StreamingCommand):
    """
    Command to convert STIX patterns to SPLUNK ones.
    """

    def _build_full_stix_pattern(self, indicator):
        """
        Adds to the STIX pattern the date constraints if they are avaialble
        """
        if "START" in indicator["pattern"] or not indicator.get("valid_from"):
            return indicator["pattern"]

        valid_from_ts: str = format_datetime(
            parse_into_datetime(indicator["valid_from"], precision="millisecond")
        )
        start_ts_str: str = f"t'{valid_from_ts}'"

        valid_until_ts = None
        if indicator.get("valid_until") is not None:
            try:
                valid_until_ts: str = parse_into_datetime(
                    indicator["valid_until"], precision="millisecond"
                )
            except Exception as parse_exception:
                self._logger.error("cannot parse valid_until: " + str(parse_exception))

        if valid_until_ts is None:
            valid_until_ts = STIXdatetime(datetime.utcnow(), precision="millisecond")
        stop_ts_str: str = f"t'{format_datetime(valid_until_ts)}'"

        return f'{indicator["pattern"]} START {start_ts_str} STOP {stop_ts_str}'

    def build_pattern(self, stranslation, record):
        """
        Build the SPLUNK pattern
        """
        indicator = json.loads(record["_raw"])
        if "[*]" in indicator["pattern"]:
            # stix_shifter doesn't support patterns like `file.hashes[*] = `
            self._logger.warning(f"Unsupported pattern: {indicator['pattern']}")
            return None

        stix_pattern = self._build_full_stix_pattern(indicator)
        try:
            pattern_splunk_res = stranslation.translate(
                module="splunk",
                translate_type=stix_translation.QUERY,
                data_source=None,
                data=stix_pattern,
                options={},
                recursion_limit=1000,
            )
        except Exception as e:
            self._logger.error(traceback.format_exc())
            return None

        if pattern_splunk_res and pattern_splunk_res.get("success") != False:
            return str(pattern_splunk_res["queries"][0])

        return None

    def stream(self, records):
        self._logger = setup_logging("ta_sekoiaio_stixtosplunk")

        stranslation = stix_translation.StixTranslation()

        for record in records:
            try:
                record["x_pattern_splunk"] = self.build_pattern(stranslation, record)
            except Exception:
                self._logger.error(traceback.format_exc())
                record["x_pattern_splunk"] = None

            yield record


if __name__ == "__main__":
    dispatch(STIXToSplunkCommand, sys.argv, sys.stdin, sys.stdout, __name__)
