#!/usr/bin/env python3
# coding: utf-8

# natives
import argparse
import os
from pathlib import Path
import tarfile
import json
from datetime import datetime

# third parties
from stix_shifter.stix_translation import stix_translation
from stix2.utils import format_datetime, get_timestamp, parse_into_datetime, STIXdatetime

# configure stix translation
STIX_TRANSLATION = stix_translation.StixTranslation()

CURSOR_FILENAME = "scan_directory.cursor"

def read_cursor(input_dir):
    cursor_path = os.path.join(input_dir, CURSOR_FILENAME)
    try:
        with open(cursor_path, 'r') as fd:
            data = fd.read()
            return json.loads(data)
    except:
        return None

def build_cursor_value(indicator_info):
    return {
        'archive_path': indicator_info['archive_path'],
        'file_path': indicator_info['file_path']
    }

def write_cursor(input_dir, cursor_value):
    cursor_path = os.path.join(input_dir, CURSOR_FILENAME)
    with open(cursor_path, 'w') as fd:
        json.dump(cursor_value, fd)

def next_archive_file(input_dir):
    cursor = read_cursor(input_dir)
    analyze_next_path = False
    for path in sorted(Path(input_dir).iterdir(), key=os.path.getctime):
        
        str_path = str(path)
        if not str_path.endswith(".tar.gz"):
            continue

        # if we are requested to analyze the followings the do so
        if analyze_next_path:
            yield str_path
        
        # no cursor indicates that we never analyzed this input dir
        # thus we analyze the current path and the followings
        elif cursor is None:
            yield str_path
            analyze_next_path = True

        # we have a cursor that shows that we have an ingoing analysis on the current
        # path. We analyze it and the followings
        elif cursor.get('archive_path') == str_path and cursor.get('file_path') != '*':
            yield str_path
            analyze_next_path = True

        # we have a curosor that show an ingoing analysis but on a concluded file
        # we analyze the followings
        elif cursor is not None and cursor['archive_path'] == str_path:
            analyze_next_path = True
              
        
def read_indicators(input_dir, archive_file):
    cursor_value = read_cursor(input_dir)
    indicator_info = None
    try:
        with tarfile.open(archive_file, "r:gz") as tar:
            analyze_next_file = False

            if cursor_value is None or cursor_value['archive_path'] != archive_file:
                analyze_next_file = True
            
            for tarinfo in tar:
                if tarinfo.isreg() and analyze_next_file:
                    file_content = tar.extractfile(tarinfo)
                    indicator_info = json.load(file_content)
                    indicator_info["archive_path"] = archive_file
                    indicator_info["file_path"] = tarinfo.name
                    yield indicator_info

                elif tarinfo.isreg() and tarinfo.name == cursor_value['file_path']:
                    analyze_next_file = True
                
        if indicator_info is not None:
            indicator_info['file_path'] = '*'
    finally:
        if indicator_info is not None:
            write_cursor(input_dir, build_cursor_value(indicator_info))
                
def read_input_dir(input_dir):
    for archive_file in next_archive_file(input_dir):
        yield from read_indicators(input_dir, archive_file)

def build_splunk_pattern(indicator):
    stix_pattern: str = indicator['pattern']

    # inject START and STOP qualifier in the pattern to denotes the valid_from and valid_until values
    if 'START' not in stix_pattern and indicator.get('valid_from') is not None:
        valid_from_ts: str = format_datetime(
            parse_into_datetime(indicator['valid_from'], precision="millisecond")
        )        
        start_ts_str: str = f"t'{valid_from_ts}'"
        
        if indicator.get('valid_until') is not None:            
            valid_until_ts: str = parse_into_datetime(indicator['valid_until'], precision="millisecond")
        else:
            valid_until_ts = STIXdatetime(datetime.utcnow(), precision = "millisecond")            
        stop_ts_str: str = f"t'{format_datetime(valid_until_ts)}'"

        stix_pattern += f' START {start_ts_str} STOP {stop_ts_str}' 

    pattern_splunk_res = STIX_TRANSLATION.translate(
        module="splunk",
        translate_type=stix_translation.QUERY,
        data_source=None,
        data=stix_pattern,
        options={},
        recursion_limit=1000
    )

    if pattern_splunk_res is not None and pattern_splunk_res.get('success') != False:
        return pattern_splunk_res['queries'][0] + " | collect index='sekoia-io-matches'"
        
    
        
def scan_directory(input_dir):
    
    for indicator_info in read_input_dir(input_dir):

        if indicator_info.get('type') == 'indicator' and 'pattern' in indicator_info:
            try:
                indicator_info['x_patern_splunk'] = build_splunk_pattern(indicator_info)
            except Exception as e:
                print(e)
                pass
        
            print(json.dumps(indicator_info))        
    
def main():

    # configure CLI arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("input", help="Input directory")
    args = parser.parse_args()
    
    # argparse
    scan_directory(
        input_dir=args.input
    )    
    

if __name__ == '__main__':
    main()


