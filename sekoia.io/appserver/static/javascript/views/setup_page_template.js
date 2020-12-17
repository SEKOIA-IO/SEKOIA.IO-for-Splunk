function get_template() {
    const template_string = `
        <h1>SEKOIA.IO Application Setup</h1>

        <div class="content">
            <div class="intro">
                <p>
                    The SEKOIA.IO Splunk Application enables you to take advantage of SEKOIA's
                    threat intelligence feed directly from your Splunk instance.
                </p>

                <p>
                    Once properly configured, this Application will continually download new Indicators
                    of Compromise from the feed and regularily look for them in your event logs.
                </p>

                <p>
                    The following IOC types are currently supported:

                    <ul>
                        <li>MD5</li>
                        <li>SHA-1</li>
                        <li>SHA-256</li>
                        <li>IPv4</li>
                        <li>Domain Name</li>
                        <li>URL</li>
                    </ul>
                </p>
            </div>

            <form id="setup">
                <div class="errors">
                </div>

                <div class="feed_setup">
                    <h2>Feed Setup</h2>
                    <label>
                        SEKOIA.IO API Key
                        <input id="api_key" type="text" name="api_key" placeholder="API Key" required />
                    </label>
                    <p class="hint">
                        API Key generated in SEKOIA.IO's User Center that should be used to access the feed content.
                        This API Key should have at least the "Intelligence Center - Read Only" role.
                    </p>

                    <label>
                        Feed ID
                        <input id="feed_id" type="text" name="feed_id" placeholder="Default feed" />
                    </label>
                    <p class="hint">
                        (optional) If you want to only fetch specific indicators, you can specify a feed ID here.
                        You can find more information on feeds in the <a href="https://docs.sekoia.io/intelligence_center/api/#feeds" target="_blank">documentation</a>.
                    </p>
                </div>

                <div class="lookups">
                    <h2>Lookups</h2>

                    <h3>MD5 Lookups</h3>
                    <a id="md5_add" href="#">+ Add MD5 Lookup</a>

                    <h3>SHA1 Lookups</h3>
                    <a id="sha1_add" href="#">+ Add SHA1 Lookup</a>

                    <h3>SHA256 Lookups</h3>
                    <a id="sha256_add" href="#">+ Add SHA256 Lookup</a>

                    <h3>IPv4 Lookups</h3>
                    <a id="ipv4_add" href="#">+ Add IPv4 Lookup</a>

                    <h3>Domain Lookups</h3>
                    <a id="domain_add" href="#">+ Add Domain Lookup</a>

                    <h3>URL Lookups</h3>
                    <a id="url_add" href="#">+ Add URL Lookup</a>
                </div>

                <input type="submit" value="Save" class="btn btn-primary" />
            </form>
        </div>
    `;

    return template_string;
  }

  function get_lookup_template(ioc_type) {
      return `
        <div class="lookup">
            <input type="hidden" name="type" value="${ioc_type}" />

            <label>
                Search Query
                <input type="text" name="search" placeholder="index=* sourcetype=..." required />
            </label>
            <p class="hint">
                All events returned by this search query will be compared with IOCs to find matches.
                Do not include time selectors, they will be automatically added.
            </p>

            <label>
                Field
                <input type="text" name="field" placeholder="${ioc_type}" required />
            </label>
            <p class="hint">
                Field that should be compared to the ${ioc_type} values
            </p>

            <a class="remove_lookup" href="#">- Remove Lookup</a>
        </div>
      `;
  }

  export {
    get_template,
    get_lookup_template
  }
