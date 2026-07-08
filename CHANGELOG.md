# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## 2026-07-08 - 1.5.2

### Fixed

- Replace deprecated "Intelligence Center - Read Only" role by new "Analyst Role" in the app setup page template

## 2026-05-21 - 1.5.1

### Added

- Add CI tests to validate the app against multiple Python versions (3.9 to 3.14), using both:
    - pip-installed dependencies
    - and the pre-bundled packages embedded in the _sekoia.io/lib/py3/_ folder
- Add CI tests to run Splunk AppInspect against the packaged app directory, to ensure Splunk compatibility checks pass on all supported Python versions
- Add missing optional bundled Python dependencies to the _sekoia.io/lib/py3/_ folder

### Fixed

- Specify Python version compatibility with `python.required: 3.13` parameter in the _sekoia.io/default/inputs.conf_ file, to pass splunk-appinspect tests

## 2025-09-05 - 1.5.0

### Fixed

- Update dependencies to the latest versions

## 2024-07-11 - 1.4.0

### Fixed

- Ignore incorrect `valid_until`

### Changed

- Update dependencies

## 2024-08-21 - 1.3.1

### Fixed

- Reinstate application

## 2024-07-30 - 1.3.0

### Changed

- Remove support of python2
- Add `case_sensitive_match` option to the configuration
- Upgrade python build time version to 3.10
- Custom wrapper over slim to have backward compatibility lower versions of python, as it is used by the splunk
