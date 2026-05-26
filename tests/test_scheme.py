"""
Test the --scheme command of the script to ensure it outputs valid XML with the expected structure.

The --scheme flag means:
- the Splunk modular input script is being asked to describe itself
- it should return an XML definition of the input parameters and metadata

Splunk uses that XML to know:
- the input name/title
- the description
- what configuration fields are required
- whether external validation or single instance mode is used

The command does not actually fetch data or connect to Splunk, it only verifies that the script loads and returns its input definition
"""

import subprocess
import sys
import xml.etree.ElementTree as ET


def test_scheme_command_outputs_valid_xml(script_path):

    # Run the script
    res = subprocess.run(
        [sys.executable, script_path, "--scheme"],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0

    # Parse XML output and check structure
    root = ET.fromstring(res.stdout)
    assert root.tag == "scheme"
    assert root.find("title") is not None
    assert root.find("description") is not None
    assert root.findall("endpoint/args/arg"), "No <arg> elements found"
