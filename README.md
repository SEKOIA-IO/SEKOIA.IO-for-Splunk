# SEKOIA.IO App for Splunk

This application detects threats in your logs by looking for Indicators of Compromise produced by SEKOIA.IO. The packaged App can be downloaded from the Release section and installed from the file.

![Splunkapp](./dashboard.png)

## Fetch IOC database

When launching the application for the first time, you will have to fill the Application Setup Page with your SEKOIA.IO API Key.

This will automatically create a configuration using modular input `sekoia_indicators` to fetch IOCs from SEKOIA.IO's Intelligence Center
and store them in separate KV-stores:

* sekoia_iocs_ipv4
* sekoia_iocs_domain
* sekoia_iocs_url
* sekoia_iocs_md5
* sekoia_iocs_sha1
* sekoia_iocs_sha256

Cleanup jobs are also created and scheduled every night to make sure that expired indicators are no longer used to detect threats.

## Perform lookups

Configure IOC lookups to actually compare incoming log events to IOCs. You can set up as many lookups as you would like by specifying:

* The query to select events from your logs. A typical query would be `index=* sourcetype=<YOUR_SOURCETYPE>`
* The field from your logs to compare with the IOC value

For each lookup, a saved search is automatically created and scheduled to run once every hour.

Sightings are stored in the `sekoia_alerts` KV-store and listed on the home Dashboard.

Clicking on the `matched_ioc` will open the Intelligence Center to see context around matched indicator.

## Proxy

There are two solutions for using the SEKOIA.IO-for-Splunk app where proxy is mandatory for Internet access.

- **You want only the SEKOIA.IO-for-Splunk app to be able to connect through the proxy.**
Without any configuration on the system, the proxy configuration must be entered through the "Proxy URL" field within the SEKOIA.IO-for-Splunk app installation page. This field accepts a value such as `http://[username:password@]host:port.`

- **You don't want to distinguish SEKOIA.IO-for-Splunk network configuration from the configuration of your Splunk instance.**
The SEKOIA.IO-for-Splunk application takes into account the global Splunk proxy configuration provided by means of the `HTTP_PROXY` and `HTTPS_PROXY` environment variables.

Note that in both cases, the proxy must support access to https://api.sekoia.io on port 443 for this to work.
