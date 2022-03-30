# Overview

Welcome to the SEKOIA.IO App for Splunk.

The SEKOIA.IO App for Splunk integrates SEKOIA.IO with Splunk Entreprise and Splunk Cloud. 
This application detects threats in your logs by looking for Indicators of Compromise produced by SEKOIA.IO.

## Main Features

- SEKOIA.IO Dashboard
  - comprehensive Overview of the available IOCs
  - view on the sighted IOCs
  - triage sightings by type of IOCs
  
- Updated database of IOCs
  - IOCs are persisted in dedicated KV-stores
  - lookup queries to compare incoming log events to IOCs
  - periodicaly refresh the IOCs
  - scheduled saved search to automaticaly hunt of new IOCs

# Requirements

- SEKOIA.IO API key

# Installation & Setup/Configuration

- Download the app or build the application from the source available on github.
- Setup the application, enter your API Key in the API Key input field.

# Resources

- Support is available on support@sekoia.io
- [Documentation](https://docs.sekoia.io)
- [Github](https://github.com/SEKOIA-IO/SEKOIA.IO-for-Splunk)
    - This project is open source and SEKOIA.IO loves open collaboration!
	- Open an issue for a bug, submit PR with your changes to UI, …
