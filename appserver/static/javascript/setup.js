"use strict";

require.config({
    paths: {
        SetupPage: "../app/sekoia.io/javascript/views/setup_page",
    },
    scriptType: "module",
});

require([
    // Splunk Web Framework Provided files
    "backbone", // From the SplunkJS stack
    "jquery", // From the SplunkJS stack
    // Custom files
    "SetupPage",
], function(Backbone, jquery, SetupPage) {
    var setup_page = new SetupPage({
        // Sets the element that will be used for rendering
        el: jquery("#setup"),
    });

    setup_page.render();
});
