"use strict";

import * as Setup from './setup_configuration.js'
import { get_template, get_lookup_template } from './setup_page_template.js'
import { APP_NAME } from "./constants.js"

define(
    ["backbone", "jquery", "splunkjs/splunk"],
    function(Backbone, jquery, splunk_js_sdk) {
        var SetupView = Backbone.View.extend({
            // -----------------------------------------------------------------
            // Backbone Functions, These are specific to the Backbone library
            // -----------------------------------------------------------------
            initialize: function initialize() {
                Backbone.View.prototype.initialize.apply(this, arguments);
            },

            events: {
                "submit": "trigger_setup",
                "click .remove_lookup": "remove_lookup",
                "click #md5_add": "add_md5_lookup",
                "click #sha1_add": "add_sha1_lookup",
                "click #sha256_add": "add_sha256_lookup",
                "click #ipv4_add": "add_ipv4_lookup",
                "click #domain_add": "add_domain_lookup",
                "click #url_add": "add_url_lookup",
            },

            render: async function() {
                this.current_settings = await this.get_current_settings();

                this.el.innerHTML = get_template();

                const input = this.current_settings['input']['sekoia_indicators://SEKOIA.IO Intelligence Center'];
                if (input) {
                    jquery('#api_key').val(input['api_key']);
                    jquery('#feed_id').val(input['feed_id']);
                }

                Object.keys(this.current_settings['lookups']).forEach((name) => {
                    if (!name.includes("Cleanup")) {
                        const ioc_type = name.split(' ')[1];
                        const template = get_lookup_template(ioc_type);
                        const matches = this.current_settings['lookups'][name]['search'].match(/(.*) \| lookup sekoia_iocs_\w+ _key as (\w+)/);

                        // Create the lookup form and complete it with current values
                        const add_link = jquery(`#${ioc_type}_add`);
                        add_link.before(template);
                        add_link.prev(".lookup").find("input[name='search']").val(matches[1]);
                        add_link.prev(".lookup").find("input[name='field']").val(matches[2]);
                    }
                });

                return this;
            },

            // -----------------------------------------------------------------
            // Custom Functions, These are unrelated to the Backbone functions
            // -----------------------------------------------------------------
            get_current_settings: async function get_current_settings() {
                const sdk_service = this.get_sdk_service(splunk_js_sdk);

                return {
                    'input': await Setup.get_input_settings(sdk_service),
                    'lookups': await Setup.get_lookup_settings(sdk_service)
                };
            },

            add_md5_lookup: function add_md5_lookup(event) {
                this.add_lookup(event, 'md5');
            },

            add_sha1_lookup: function add_sha1_lookup(event) {
                this.add_lookup(event, 'sha1');
            },

            add_sha256_lookup: function add_sha256_lookup(event) {
                this.add_lookup(event, 'sha256');
            },

            add_ipv4_lookup: function add_ipv4_lookup(event) {
                this.add_lookup(event, 'ipv4');
            },

            add_domain_lookup: function add_domain_lookup(event) {
                this.add_lookup(event, 'domain');
            },

            add_url_lookup: function add_url_lookup(event) {
                this.add_lookup(event, 'url');
            },

            add_lookup: function add_lookup(event, ioc_type) {
                event.preventDefault();

                const template = get_lookup_template(ioc_type);
                jquery(event.target).before(template);
            },

            remove_lookup: function remove_lookup(event) {
                event.preventDefault();
                jquery(event.target).parent().remove();
            },

            // ----------------------------------
            // Main Setup Logic
            // ----------------------------------
            // This performs some sanity checking and cleanup on the inputs that
            // the user has provided before kicking off main setup process
            trigger_setup: function trigger_setup(event) {
                event.preventDefault();
                console.log("Triggering setup");

                // Used to hide the error output, when a setup is retried
                this.display_error_output([]);

                // Parse form and apply settings
                const settings = this.parse_form();
                this.perform_setup(splunk_js_sdk, settings);
            },

            // Parse form inputs to return formatted objects
            parse_form: function parse_form() {
                const values = jquery("form#setup").serializeArray();

                // Extract Feed Settings
                const feed_settings = {
                    api_key: values[0].value.trim(),
                    feed_id: values[1].value.trim()
                };

                // Extract Lookups
                const lookups = new Array();
                var i = 0;

                while (i * 3 + 2 < values.length) {
                    const offset = 2 + i * 3;
                    lookups.push({
                        type: values[offset].value.trim(),
                        query: values[offset + 1].value.trim(),
                        field: values[offset + 2].value.trim(),
                    });
                    ++i;
                }

                return {
                    feed_settings,
                    lookups
                };
            },

            get_sdk_service: function get_sdk_service(splunk_js_sdk) {
                var application_name_space = {
                    owner: "nobody",
                    app: APP_NAME,
                    sharing: "app",
                };

                return Setup.create_splunk_js_sdk_service(splunk_js_sdk, application_name_space);
            },

            // This is where the main setup process occurs
            perform_setup: async function perform_setup(splunk_js_sdk, settings) {
                try {
                    // Create the Splunk JS SDK Service object
                    const splunk_js_sdk_service = this.get_sdk_service(splunk_js_sdk);

                    let { feed_settings, lookups } = settings;

                    // Configure modular input
                    await Setup.setup_modular_input(splunk_js_sdk_service, feed_settings);

                    // Configure saved searches
                    await Setup.setup_lookups(splunk_js_sdk_service, lookups);

                    // Setup IOC cleanup
                    await Setup.setup_cleanup(splunk_js_sdk_service);

                    // // Completes the setup, by access the app.conf's [install]
                    // // stanza and then setting the `is_configured` to true
                    // await Setup.complete_setup(splunk_js_sdk_service);

                    // // Reloads the splunk app so that splunk is aware of the
                    // // updates made to the file system
                    // await Setup.reload_splunk_app(splunk_js_sdk_service, APP_NAME);

                    // // Redirect to the Splunk App's home page
                    // Setup.redirect_to_splunk_app_homepage(APP_NAME);
                } catch (error) {
                    var error_messages_to_display = [];
                    if (
                        error !== null &&
                        typeof error === "object" &&
                        error.hasOwnProperty("responseText")
                    ) {
                        var response_object = JSON.parse(error.responseText);
                        error_messages_to_display = this.extract_error_messages(
                            response_object.messages,
                        );
                    } else {
                        // Assumed to be string
                        error_messages_to_display.push(error);
                    }

                    this.display_error_output(error_messages_to_display);
                }
            },

            // ----------------------------------
            // GUI Helpers
            // ----------------------------------
            extract_error_messages: function extract_error_messages(error_messages) {
                // A helper function to extract error messages

                // Expects an array of messages
                // [
                //     {
                //         type: the_specific_error_type_found,
                //         text: the_specific_reason_for_the_error,
                //     },
                //     ...
                // ]

                var error_messages_to_display = [];
                for (var index = 0; index < error_messages.length; index++) {
                    const error_message = error_messages[index];
                    const error_message_to_display = error_message.type + ": " + error_message.text;
                    error_messages_to_display.push(error_message_to_display);
                }

                return error_messages_to_display;
            },

            // ----------------------------------
            // Display Functions
            // ----------------------------------
            display_error_output: function display_error_output(error_messages) {
                // Hides the element if no messages, shows if any messages exist
                var did_error_messages_occur = error_messages.length > 0;

                var error_output_element = jquery(".content .errors");

                if (did_error_messages_occur) {
                    var new_error_output_string = "";
                    new_error_output_string += "<ul>";
                    for (var index = 0; index < error_messages.length; index++) {
                        new_error_output_string +=
                            "<li>" + error_messages[index] + "</li>";
                    }
                    new_error_output_string += "</ul>";

                    error_output_element.html(new_error_output_string);
                    error_output_element.stop();
                    error_output_element.fadeIn();
                } else {
                    error_output_element.stop();
                    error_output_element.fadeOut({
                        complete: function() {
                            error_output_element.html("");
                        },
                    });
                }
            },
        }); // End of SetupView class declaration

        return SetupView;
    }, // End of require asynchronous module definition function
); // End of require statement
