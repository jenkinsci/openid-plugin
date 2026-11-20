/*
 * Handlers for the OpenID user property configuration page.
 *
 * Kept in an external file because Jenkins enables a Content Security Policy
 * that blocks inline scripts and inline event handlers.
 */
(function () {
    "use strict";

    if (window.__openidConfigInitialized) {
        return;
    }
    window.__openidConfigInitialized = true;

    document.addEventListener("click", function (event) {
        var button = event.target.closest ? event.target.closest("input.openid-delete") : null;
        if (!button) {
            return;
        }
        var item = button.closest("li");
        if (item) {
            item.remove();
        }
    });
})();
