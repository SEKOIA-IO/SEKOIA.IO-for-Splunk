from __future__ import print_function

import os
import sys
import time
import traceback
from datetime import datetime
from collections import defaultdict
from posixpath import join as urljoin

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

import six  # noqa: E402
import requests  # noqa: E402
import splunklib.client as client  # noqa: E402
from stix2patterns.pattern import Pattern  # noqa: E402
from splunklib.modularinput import Script, Scheme, Argument  # noqa: E402


DEFAULT_FEED = "d6092c37-d8d7-45c3-8aff-c4dc26030608"
BASE_URL = "https://api.sekoia.io/v2/inthreat/"
LIMIT = 300
COLLECTION_NAME = "sekoia_iocs_{}"
SUPPORTED_TYPES = {
    "ipv4-addr": {"value": "ipv4"},
    "domain-name": {"value": "domain"},
    "url": {"value": "url"},
    "file": {"hashes.MD5": "md5", "hashes.SHA-1": "sha1", "hashes.SHA-256": "sha256"},
}


def from_rfc3339(date_string):
    try:
        return datetime.strptime(date_string, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return datetime.strptime(date_string, "%Y-%m-%dT%H:%M:%SZ")


class SEKOIAIndicators(Script):
    def __init__(self):
        self._splunk = None
        self._kv_stores = {}

    # Get current feed cursor (splunk checkpoint)
    def get_cursor(self, inputs, feed_id):
        cursor_path = os.path.join(inputs.metadata["checkpoint_dir"], "{}.cursor".format(feed_id))

        if os.path.isfile(cursor_path):
            with open(cursor_path, "r") as f:
                return f.read()

        return None

    # Store current feed cursor
    def store_cursor(self, inputs, feed_id, cursor):
        cursor_path = os.path.join(inputs.metadata["checkpoint_dir"], "{}.cursor".format(feed_id))

        with open(cursor_path, "w") as f:
            f.write(cursor)

    # Fetch indicator batches from the Intelligence Center
    def get_indicators(self, inputs):
        for input_name, input_item in six.iteritems(inputs.inputs):
            feed_id = input_item.get("feed_id", "") or DEFAULT_FEED
            cursor = self.get_cursor(inputs, feed_id)

            url = urljoin(
                BASE_URL,
                "collections",
                feed_id,
                "objects?match[type]=indicator&limit={}".format(LIMIT),
            )
            paginated_url = url

            while True:
                if cursor:
                    paginated_url = "{}&cursor={}".format(url, cursor)

                response = requests.get(
                    paginated_url,
                    headers={"Authorization": "Bearer {}".format(input_item["api_key"])},
                )
                response.raise_for_status()
                data = response.json()

                cursor = data["next_cursor"]
                self.store_cursor(inputs, feed_id, cursor)

                yield data["items"]

                if not data["items"] or len(data["items"]) < LIMIT:
                    break

    # Convert a STIX 2.1 Indicator to Splunk key-value objects
    def indicator_to_kv(self, indicator):
        parsed_pattern = Pattern(indicator["pattern"])
        results = defaultdict(list)

        for observable_type, comparisons in six.iteritems(parsed_pattern.inspect().comparisons):
            for path, operator, value in comparisons:
                if observable_type not in SUPPORTED_TYPES:
                    print(
                        "WARNING Unsupported type '{}' in pattern '{}'".format(
                            observable_type, indicator["pattern"]
                        ),
                        file=sys.stderr,
                    )
                    continue

                try:
                    path = ".".join(path)
                except TypeError:
                    # This happends when the pattern contains '*', which is unsupported by the Splunk App
                    print(
                        "WARNING Unsupported path '*' in pattern '{}'".format(
                            indicator["pattern"]
                        ),
                        file=sys.stderr,
                    )
                    continue

                if path not in SUPPORTED_TYPES[observable_type]:
                    print(
                        "WARNING Unsupported path '{}' in pattern '{}'".format(
                            path, indicator["pattern"]
                        ),
                        file=sys.stderr,
                    )
                    continue

                if operator != "=":
                    print(
                        "WARNING Unsupported operator '{}' in pattern '{}'".format(
                            operator, indicator["pattern"]
                        ),
                        file=sys.stderr,
                    )
                    continue

                result = {
                    "_key": value.strip("'"),
                    "indicator_id": indicator["id"],
                    "valid_until": indicator.get("valid_until"),
                }

                if indicator.get("valid_until"):
                    result["valid_until"] = int(
                        time.mktime(
                            datetime.strptime(
                                indicator["valid_until"][:19], "%Y-%m-%dT%H:%M:%S"
                            ).timetuple()
                        )
                    )

                results[SUPPORTED_TYPES[observable_type][path]].append(result)

        return results

    # Get IOC Type Key-Value stores on demand
    def get_kvstore(self, ioc_type):
        store_name = COLLECTION_NAME.format(ioc_type)

        if store_name not in self._kv_stores:

            # Create KV Store if it doesn't exist
            if store_name not in self._splunk.kvstore:
                self._splunk.kvstore.create(store_name)

            self._kv_stores[store_name] = self._splunk.kvstore[store_name].data

        return self._kv_stores[store_name]

    # Delete revoked indicator from Splunk KV-Stores
    def revoke_indicator(self, kv_objects):
        for ioc_type, objects in six.iteritems(kv_objects):
            for obj in objects:
                try:
                    self.get_kvstore(ioc_type).delete_by_id(obj["_key"])
                except Exception:
                    pass

    # Store indicators in Splunk KV-Stores
    def store_indicators(self, indicators):
        objects = defaultdict(list)
        now = datetime.utcnow()

        for indicator in indicators:
            kv_objects = self.indicator_to_kv(indicator)

            if indicator.get("revoked", False):
                self.revoke_indicator(kv_objects)
            # Only import IOCs with a Valid Until date set
            elif indicator.get("valid_until"):
                # Ignore expired indicators
                valid_until = from_rfc3339(indicator["valid_until"])
                if valid_until > now:
                    for ioc_type, dicts in six.iteritems(kv_objects):
                        objects[ioc_type] += dicts

        for ioc_type, batch in six.iteritems(objects):
            self.get_kvstore(ioc_type).batch_save(*batch)
            print("INFO Saved KVStore Batch of {} IOCs of type {}".format(len(batch), ioc_type))

    # Describe the Modular Input and its arguments
    def get_scheme(self):
        scheme = Scheme("SEKOIA.IO Intelligence Center feed")
        scheme.description = "Fetch indicators from the Intelligence Center"

        scheme.use_external_validation = True
        scheme.use_single_instance = True

        api_key = Argument("api_key")
        api_key.title = "API Key"
        api_key.data_type = Argument.data_type_string
        api_key.description = (
            "SEKOIA.IO API Key to use to access the feed."
            "Contact support@sekoia.io if you are not sure how to get this API Key."
        )
        api_key.required_on_create = True
        scheme.add_argument(api_key)

        feed_id = Argument("feed_id")
        feed_id.title = "Feed ID"
        feed_id.data_type = Argument.data_type_string
        feed_id.description = "Specific Feed ID to use as IOC source."
        feed_id.required_on_create = False
        feed_id.required_on_edit = False
        scheme.add_argument(feed_id)

        return scheme

    # Validate the Modular Input's configuration
    def validate_input(self, validation_definition):
        # Validates input.
        return True

    # Method called by Splunk to get new events
    def stream_events(self, inputs, ew):
        while True:
            try:
                self._splunk = client.connect(
                    token=self._input_definition.metadata["session_key"], owner="nobody"
                )

                for indicators in self.get_indicators(inputs):
                    self.store_indicators(indicators)
            except Exception:
                exception = traceback.format_exc()

                for line in exception.splitlines():
                    print("ERROR {}".format(line), file=sys.stderr)
            finally:
                print("INFO Done fetching indicators, sleeping for 10 minutes.")
                time.sleep(600)


if __name__ == "__main__":
    sys.exit(SEKOIAIndicators().run(sys.argv))
