import * as SplunkHelpers from "./splunk_helpers.js";
import { APP_NAME } from "./constants.js";

async function setup_modular_input(splunk_js_sdk_service, properties) {
  await SplunkHelpers.update_configuration_file(
    splunk_js_sdk_service,
    "inputs",
    "sekoia_indicators://feed",
    properties
  );
}

async function get_input_settings(splunk_js_sdk_service) {
  return await SplunkHelpers.get_configuration(splunk_js_sdk_service, "inputs");
}

async function get_lookup_settings(splunk_js_sdk_service) {
  return await SplunkHelpers.get_configuration(
    splunk_js_sdk_service,
    "savedsearches"
  );
}

async function setup_lookups(splunk_js_sdk_service, lookups) {
  const CRON_SCHEDULES = {
    ipv4: "10 * * * *",
    domain: "15 * * * *",
    url: "20 * * * *",
    md5: "25 * * * *",
    sha1: "30 * * * *",
    sha256: "35 * * * *",
  };

  var searches = splunk_js_sdk_service.savedSearches();
  await searches.fetch();

  // Delete all currently setup Saved Searches for our app
  const previousSearches = searches.list();
  for (var index = 0; index < previousSearches.length; index++) {
    if (previousSearches[index].namespace.app === APP_NAME) {
      await previousSearches[index].del();
    }
  }

  // Create all configured lookups
  for (index = 0; index < lookups.length; index++) {
    const lookup = {
      name: `SEKOIA.IO ${lookups[index].type} lookup ${index}`,
      search: `${lookups[index].query} | lookup sekoia_iocs_${lookups[index].type} _key as ${lookups[index].field} OUTPUTNEW _key as matched_ioc indicator_id as indicator_id | search matched_ioc=* | eval event=_raw, event_time=_time, sighting_hash=sha256(host.index.sourcetype.event), ioc_type="${lookups[index].type}" | fields event_time,matched_ioc,ioc_type,indicator_id,host,index,sourcetype,event,sighting_hash | outputlookup sekoia_alerts append=true key_field=sighting_hash`,
      "dispatch.earliest_time": "-65m@m",
      "dispatch.latest_time": "-5m@m",
      is_scheduled: 1,
      cron_schedule: CRON_SCHEDULES[lookups[index].type],
    };

    searches.create(lookup);
  }
}

async function setup_cleanup(splunk_js_sdk_service) {
  const CRON_SCHEDULES = {
    ipv4: "40 2 * * *",
    domain: "45 2 * * *",
    url: "50 2 * * *",
    md5: "55 2 * * *",
    sha1: "0 2 * * *",
    sha256: "5 2 * * *",
  };
  const ioc_types = Object.keys(CRON_SCHEDULES);

  var searches = splunk_js_sdk_service.savedSearches();
  await searches.fetch();

  for (var index = 0; index < ioc_types.length; index++) {
    const cleanup = {
      name: `SEKOIA.IO IOC Cleanup - ${ioc_types[index]}`,
      search: `| inputlookup sekoia_iocs_${ioc_types[index]} | convert num(valid_until) | where isNull(valid_until) OR valid_until > now() | outputlookup sekoia_iocs_${ioc_types[index]}`,
      is_scheduled: 1,
      cron_schedule: CRON_SCHEDULES[ioc_types[index]],
    };

    searches.create(cleanup);
  }
}

async function create_custom_configuration_file(
  splunk_js_sdk_service,
  api_url
) {
  var custom_configuration_file_name = "setup_page_example";
  var stanza_name = "example_stanza";
  var properties_to_update = {
    api_url: api_url,
  };

  await SplunkHelpers.update_configuration_file(
    splunk_js_sdk_service,
    custom_configuration_file_name,
    stanza_name,
    properties_to_update
  );
}

async function complete_setup(splunk_js_sdk_service) {
  var configuration_file_name = "app";
  var stanza_name = "install";
  var properties_to_update = {
    is_configured: "true",
  };

  await SplunkHelpers.update_configuration_file(
    splunk_js_sdk_service,
    configuration_file_name,
    stanza_name,
    properties_to_update
  );
}

async function reload_splunk_app(splunk_js_sdk_service, app_name) {
  var splunk_js_sdk_apps = splunk_js_sdk_service.apps();
  await splunk_js_sdk_apps.fetch();

  var current_app = splunk_js_sdk_apps.item(app_name);
  current_app.reload();
}

function redirect_to_splunk_app_homepage(app_name) {
  var redirect_url = "/app/" + app_name;

  window.location.href = redirect_url;
}

function create_splunk_js_sdk_service(splunk_js_sdk, application_name_space) {
  var http = new splunk_js_sdk.SplunkWebHttp();

  var splunk_js_sdk_service = new splunk_js_sdk.Service(
    http,
    application_name_space
  );

  return splunk_js_sdk_service;
}

export {
  create_custom_configuration_file,
  complete_setup,
  reload_splunk_app,
  redirect_to_splunk_app_homepage,
  create_splunk_js_sdk_service,
  setup_modular_input,
  get_input_settings,
  get_lookup_settings,
  setup_lookups,
  setup_cleanup,
};
