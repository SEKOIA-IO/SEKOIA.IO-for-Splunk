from __future__ import print_function

import os
import sys
import time
import traceback
from collections import defaultdict
from datetime import datetime
from posixpath import join as urljoin

if sys.version_info[0] < 3:
    py_version = "py2"
else:
    py_version = "py3"

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib", py_version))

import requests  # noqa: E402
import six  # noqa: E402
import splunklib.client as client  # noqa: E402
from splunklib.binding import HTTPError  # noqa: E402
from splunklib.modularinput import Argument, Scheme, Script  # noqa: E402
from stix2patterns.pattern import Pattern  # noqa: E402

SEKOIAIO_REALM = "sekoiaio_realm"
MASK = "<nothing to see here>"
DEFAULT_FEED = "d6092c37-d8d7-45c3-8aff-c4dc26030608"
BASE_URL = "https://api.sekoia.io"
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
    def __init__(self, *args, **kwargs):
        super(SEKOIAIndicators, self).__init__(*args, **kwargs)
        self._splunk = None
        self._kv_stores = {}

    # Get current feed cursor (splunk checkpoint)
    def get_cursor(self, inputs, feed_id):
        cursor_path = os.path.join(
            inputs.metadata["checkpoint_dir"], "{}.cursor".format(feed_id)
        )

        if os.path.isfile(cursor_path):
            with open(cursor_path, "r") as f:
                return f.read()

        return None

    # Store current feed cursor
    def store_cursor(self, inputs, feed_id, cursor):
        cursor_path = os.path.join(
            inputs.metadata["checkpoint_dir"], "{}.cursor".format(feed_id)
        )

        with open(cursor_path, "w") as f:
            f.write(cursor)

    def _store_api_key_in_secured_storage(self, feed_id, api_key, ew):
        """
        Stores the API keyi in the secured storage
        """

        # delete if it exists
        for secret in self.service.storage_passwords:

            if secret.realm == SEKOIAIO_REALM and secret.username == feed_id:
                secret.delete()
                ew.log(ew.INFO, "Secret for the same feed has been deleted")

        storage_password = self.service.storage_passwords.create(
            api_key, feed_id, SEKOIAIO_REALM
        )
        ew.log(
            ew.INFO,
            f"API key succesffuly stored in the secured storage under {storage_password.name}",
        )

        return storage_password

    def _get_api_key_from_secured_storage(self, feed_id):
        """
        Reads the secured storage for the API key
        """
        for secret in self.service.storage_passwords:

            if secret.realm == SEKOIAIO_REALM and secret.username == feed_id:
                return secret.clear_password

        raise ValueError("No api-key found in secured storage for the feed")

    def _mask_api_key(self, session_key, input_name, feed_id, ew):
        """
        Mask the api key in the input configuration
        """
        ew.log(ew.INFO, f"Masking api key for feed {feed_id} in input configuration")
        kind, input_name_path = input_name.split("://")
        item = self.service.inputs.__getitem__((input_name_path, kind))
        kwargs = {"feed_id": feed_id, "api_key": MASK}
        ew.log(ew.INFO, f"Retrieved the input to update: {item} - {kwargs}")

        item.update(**kwargs).refresh()
        ew.log(ew.INFO, "Input succesfully updated")

    def get_indicators(
        self, feed_id, api_key, api_root_url=None, proxy_url=None, cursor=None, ew=None
    ):
        """
        Fetch and yelds indicators from the configuration feed
        """

        if ew:
            ew.log(
                ew.INFO,
                f"Fetch indicators from feed_id={feed_id} (api_root_url={api_root_url})",
            )

        proxies = None

        if proxy_url:
            proxies = {"http": proxy_url, "https": proxy_url}
            if ew:
                ew.log(
                    ew.DEBUG, f"Configure network proxy access with proxy={proxy_url}"
                )

        url_root = BASE_URL
        if api_root_url:
            url_root = api_root_url

        url = urljoin(
            url_root+"/",
            "v2/inthreat/collections",
            feed_id,
            "objects?match[type]=indicator&limit={}".format(LIMIT),
        )
        paginated_url = url

        while True:
            if cursor:
                paginated_url = "{}&cursor={}".format(url, cursor)

            response = requests.get(
                paginated_url,
                headers={"Authorization": "Bearer {}".format(api_key)},
                proxies=proxies,
            )
            if ew:
                ew.log(
                    ew.DEBUG,
                    "API call on {url} returned an HTTP status-code={response.status_code}",
                )

            response.raise_for_status()
            data = response.json()

            cursor = data["next_cursor"]

            yield (cursor, data["items"])

            if not data["items"] or len(data["items"]) < LIMIT:
                break

    # Convert a STIX 2.1 Indicator to Splunk key-value objects
    def indicator_to_kv(self, indicator, api_root_url):
        results = defaultdict(list)
        pattern_type = indicator.get("pattern_type")

        if pattern_type is not None and pattern_type != "stix":
            print(
                "WARNING Unsupported pattern type '{}'".format(pattern_type),
                file=sys.stderr,
            )
            return results

        parsed_pattern = Pattern(indicator["pattern"])

        for observable_type, comparisons in six.iteritems(
            parsed_pattern.inspect().comparisons
        ):
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

                # KV store that hosts the IOC leverage
                # an accelerated field to support fast enrichment.
                #
                # Unfortunately, Splunk Accelerated Fields
                # cannot be larger than 1024.
                if len(value.strip("'")) <= 1024:

                    if not api_root_url:
                        server_root_url = "https://app.sekoia.io"
                    else:
                        server_root_url = api_root_url
                        if server_root_url.endswith("/api"):
                            server_root_url = server_root_url[:-4]
                        elif server_root_url.endswith("/api/"):
                            server_root_url = server_root_url[:-5]

                    # Applying _key to lowercase to avoid case sensitivity
                    result = {
                        "_key": value.strip("'").lower(),
                        "indicator_id": indicator["id"],
                        "server_root_url": server_root_url,
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

    def store_indicators(self, indicators, ew, api_root_url):
        """
        Stores the indicators in the Splunk KV-Stores
        """
        objects = defaultdict(list)
        now = datetime.utcnow()

        for indicator in indicators:
            kv_objects = self.indicator_to_kv(indicator, api_root_url)

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
            try:
                self.get_kvstore(ioc_type).batch_save(*batch)
            except HTTPError as http_error:
                ew.log(ew.ERROR, "Failed to persist batch in kvstore")
                ew.log(ew.ERROR, http_error)

            ew.log(
                ew.INFO, f"Saved KVStore Batch of {len(batch)} IOCs of type {ioc_type}"
            )

    # Describe the Modular Input and its arguments
    def get_scheme(self):
        scheme = Scheme("SEKOIA.IO Intelligence Center feed")
        scheme.description = "Fetch indicators from the Intelligence Center"

        scheme.use_external_validation = True
        scheme.use_single_instance = True

        # api key
        api_key = Argument("api_key")
        api_key.title = "API Key"
        api_key.data_type = Argument.data_type_string
        api_key.description = (
            "SEKOIA.IO API Key to use to access the feed."
            "Contact support@sekoia.io if you are not sure how to get this API Key."
        )
        api_key.required_on_create = True
        scheme.add_argument(api_key)

        # feed id
        feed_id = Argument("feed_id")
        feed_id.title = "Feed ID"
        feed_id.data_type = Argument.data_type_string
        feed_id.description = "Specific Feed ID to use as IOC source."
        feed_id.required_on_create = False
        feed_id.required_on_edit = False
        scheme.add_argument(feed_id)

        # api root url
        api_root_url = Argument("api_root_url")
        api_root_url.title = "SEKOIA.IO API URL"
        api_root_url.data_type = Argument.data_type_string
        api_root_url.description = "(optional) URL root of your SEKOIA.IO TIP API (e.g. https://api.sekoia.io or https://my.sekoiaio.tip.local/api)"
        api_root_url.required_on_create = False
        api_root_url.required_on_edit = False
        scheme.add_argument(api_root_url)

        # proxy url
        proxy_url = Argument("proxy_url")
        proxy_url.title = "Proxy URL"
        proxy_url.data_type = Argument.data_type_string
        proxy_url.description = (
            "(Optional) URL of the proxy server to use for HTTPS requests to SEKOIA.IO. "
            "The proxy URL can optionally contain an username and password if basic authentication is needed."
        )
        proxy_url.required_on_create = False
        proxy_url.required_on_edit = False
        scheme.add_argument(proxy_url)

        return scheme

    # Validate the Modular Input's configuration
    def validate_input(self, definition):
        """
        Triggers before creating the new input with the provided details
        to check the configuration is valid.

        It performs the following checks:
        - checks it can connects to the feed to retrieve few indicators
        """

        try:
            feed_id = definition.parameters["feed_id"] or DEFAULT_FEED
            api_key = definition.parameters["api_key"]
            api_root_url = definition.parameters.get("api_root_url")
            proxy_url = definition.parameters.get("proxy_url")
            if api_key == MASK:
                return True

            (cursor, indicators) = next(
                self.get_indicators(
                    feed_id=feed_id,
                    api_key=api_key,
                    api_root_url=api_root_url,
                    proxy_url=proxy_url,
                )
            )
        except requests.exceptions.HTTPError as http_error:
            raise Exception(f"Failed to connect on SEKOIA.IO feed: {http_error}")

        return True

    # Method called by Splunk to get new events
    def stream_events(self, inputs, ew):

        while True:

            self._splunk = client.connect(
                token=self._input_definition.metadata["session_key"], owner="nobody"
            )

            ew.log(ew.INFO, "Getting new events with the SEKOIA.IO modular input")

            session_key = self._input_definition.metadata["session_key"]
            # trigger the encryption of the api key if not yet performed
            for input_name, input_item in six.iteritems(inputs.inputs):
                feed_id = input_item.get("feed_id", DEFAULT_FEED)
                api_key = input_item["api_key"]
                if api_key != MASK:
                    self._store_api_key_in_secured_storage(feed_id, api_key, ew)
                    self._mask_api_key(session_key, input_name, feed_id, ew)

            try:
                for input_name, input_item in six.iteritems(inputs.inputs):
                    ew.log(ew.INFO, f"Fetch the indicators for input {input_name}")
                    try:
                        feed_id = input_item.get("feed_id", "") or DEFAULT_FEED
                        proxy_url = input_item.get("proxy_url")
                        api_root_url = input_item.get("api_root_url")
                        api_key = self._get_api_key_from_secured_storage(
                            feed_id=feed_id
                        )
                        cursor = self.get_cursor(inputs, feed_id)

                        for cursor, indicators in self.get_indicators(
                            feed_id=feed_id,
                            api_key=api_key,
                            api_root_url=api_root_url,
                            proxy_url=proxy_url,
                            cursor=cursor,
                            ew=ew,
                        ):
                            self.store_indicators(indicators, ew, api_root_url)
                            self.store_cursor(inputs, feed_id, cursor)

                    except Exception:
                        exception = traceback.format_exc()

                        for line in exception.splitlines():
                            ew.log(ew.ERROR, line)
            finally:
                ew.log(
                    ew.INFO,
                    "Done fetching indicators of all the SEKOIA.IO inputs, sleeping for 10 minutes.",
                )
                time.sleep(600)


if __name__ == "__main__":
    sys.exit(SEKOIAIndicators().run(sys.argv))
