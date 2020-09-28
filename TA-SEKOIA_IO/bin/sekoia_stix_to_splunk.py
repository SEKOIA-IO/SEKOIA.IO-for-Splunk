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
from splunklib.searchcommands import (
    dispatch,
    StreamingCommand,
    Configuration
)
from splunklib import client
from stix_shifter.stix_translation import stix_translation
from stix2.utils import format_datetime, get_timestamp, parse_into_datetime, STIXdatetime

# internals
from utils import setup_logging

class ConversionError(Exception):
    pass

@Configuration()
class STIXToSplunkCommand(StreamingCommand):

    def build_pattern(self, stranslation, record):
        indicator = json.loads(record['_raw'])
        stix_pattern = indicator['pattern']

        if 'START' not in stix_pattern and indicator.get('valid_from') is not None:
            valid_from_ts: str = format_datetime(
                parse_into_datetime(indicator['valid_from'], precision="millisecond")
            )        
            start_ts_str: str = f"t'{valid_from_ts}'"

            valid_until_ts = None
            if indicator.get('valid_until') is not None:
                try:
                    valid_until_ts: str = parse_into_datetime(indicator['valid_until'], precision="millisecond")
                except Exception as parse_exception:
                    self._logger.error("cannot parse valid_until: "+str(parse_exception))
                    
            if valid_until_ts is None:
                valid_until_ts = STIXdatetime(datetime.utcnow(), precision = "millisecond")            
            stop_ts_str: str = f"t'{format_datetime(valid_until_ts)}'"

            stix_pattern += f' START {start_ts_str} STOP {stop_ts_str}' 
            
        try:            
            pattern_splunk_res = stranslation.translate(
                module="splunk",
                translate_type=stix_translation.QUERY,
                data_source=None,
                data=stix_pattern,
                options={},
                recursion_limit=1000
            )
        except Exception as e:
            # self._logger.error(traceback.format_exc())
            pass

        if pattern_splunk_res is not None and pattern_splunk_res.get('success') != False:
            return str(pattern_splunk_res['queries'][0])

        return None

    
    def stream(self, records):
        self._logger = setup_logging("ta_sekoiaio_stixtosplunk")
        self._logger.info("foo")

        stranslation = stix_translation.StixTranslation()

        for record in records:
            self._logger.info(record)
            try:
                res = self.build_pattern(stranslation, record)
                if res:
                    record["x_pattern_splunk"] = res
            except Exception as pattern_exception:
                self._logger.error(traceback.format_exc())
            yield record
            
            
            

if __name__ == "__main__":
    dispatch(STIXToSplunkCommand, sys.argv, sys.stdin, sys.stdout, __name__)
