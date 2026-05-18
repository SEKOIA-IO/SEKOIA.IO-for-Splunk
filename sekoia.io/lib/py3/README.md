# Bundled dependencies

## Purpose

Splunk apps cannot rely on packages installed in the system Python environment because Splunk manages its own Python runtime and does not expose the host's site-packages.

Third-party dependencies must therefore be shipped **inside the app itself**, under _sekoia.io/lib/py3/_.

Splunk automatically adds this directory to `sys.path` at runtime, making the bundled packages available to the app's Python scripts.

## Required dependencies

These packages are mandatory for the app to function and are always bundled:

| Package | Version | Purpose |
|---|---|---|
| antlr4-python3-runtime | 4.9.3 | STIX2 pattern parser runtime (required by stix2-patterns) |
| deprecation | 2.1.0 | Deprecation utilities (required by stix2-patterns) |
| packaging | 25.0 | Version parsing utilities |
| requests | 2.32.5 | HTTP client used to fetch IOCs from the SEKOIA.IO Intelligence Center API |
| six | 1.17.0 | Python 2/3 compatibility shim (required by stix2-patterns) |
| splunk-sdk | 2.1.1 | Splunk Python SDK, used to interact with KV-stores and saved searches |
| stix2-patterns | 2.0.0 | STIX2 indicator pattern parsing and validation |

## Optional dependencies (bundled for CI purposes)

The following packages are **not strictly required** to be bundled because they are already available in the Splunk SOAR (Cloud) runtime environment.

However, embedding them allows the CI pipeline to run robust tests against the bundled packages in isolation (via `PYTHONPATH=sekoia.io/lib/py3`), without relying on any system-installed packages.

| Package | Version |
|---|---|
| certifi | 2026.4.22 |
| charset-normalizer | 3.4.7 |
| idna | 3.13 |
| urllib3 | 2.6.3 |

See the [Splunk SOAR documentation](https://help.splunk.com/en/splunk-soar/soar-cloud/develop-apps/develop-apps/develop-an-app-using-the-splunk-soar-app-wizard/app-structure/frequently-asked-questions) for the full list of packages pre-available in the Splunk SOAR Cloud environment.
