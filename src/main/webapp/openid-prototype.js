/*
 * Simple OpenID Plugin
 * https://code.google.com/p/openid-selector/
 * This code is licensed under the New BSD License.
*/

/* jslint browser: true */
/* global $, jQuery */

/*
 * Modern Jenkins no longer bundles Prototype.js, so provide the single
 * helper this file still uses.
 */
if (typeof $ !== 'function') {
    $ = function(id) {
        return document.getElementById(id);
    };
}

var openid = {
    version: '1.3-beta1', // version constant
    cookie_expires: 6 * 30, // 6 months.
    identifier_cookie_name: 'openid_identifier',
    cookie_path: '/',

    img_path: 'images/',
    signin_text: null, // text on submit button on the form
    input_id: null,

    /**
     * Class constructor
     *
     * @return {Void}
     */
    init: function(input_id) {
        "use strict";
        this.input_id = input_id;

        // Hosted OpenID providers have all shut down, so the form only asks
        // for a custom OpenID identifier, which is shown directly.
        $('openid_form').onsubmit = this.onsubmit;
        this.showInput();

        var identifier = this.readCookie(this.identifier_cookie_name);
        if (identifier) {
            this.restoreIdentifier(identifier);
        }
    },

    /**
     * Render the custom OpenID identifier input.
     *
     * @return {Void}
     */
    showInput: function() {
        var input_area = $('openid_input_area');
        var html = '<p>Enter your OpenID.</p>' +
            '<input id="' + this.input_id + '" type="text" class="jenkins-input" ' +
            'style="background: #FFF url(' + this.img_path + 'openid-inputicon.gif) no-repeat scroll 0 50%; padding-left:18px;" ' +
            'name="' + this.input_id + '" value="https://" />' +
            '<button id="openid_submit" type="submit" class="jenkins-button jenkins-button--primary">' + this.signin_text + '</button>';
        input_area.innerHTML = html;
        $('openid_submit').onclick = this.submit;
        document.getElementById(this.input_id).focus();
    },

    /**
     * Sign-in button click
     *
     * @return {Boolean}
     */
    submit: function() {
        if (openid.onsubmit())
            $('openid_form').submit();
    },

    onsubmit: function() {
        var input = document.getElementById(openid.input_id);
        var url = input ? input.value : '';
        if (url && url != 'https://') {
            openid.setCookie(url, openid.identifier_cookie_name);
        }
        return true;
    },

    restoreIdentifier: function(identifier) {
        var input = document.getElementById(this.input_id);
        if (input) {
            input.value = identifier;
        }
    },

    setCookie: function(value, name) {
        name = name || this.identifier_cookie_name;
        var date = new Date();
        date.setTime(date.getTime() + (this.cookie_expires * 24 * 60 * 60 * 1000));
        var expires = "; expires=" + date.toGMTString();
        document.cookie = name + "=" + encodeURIComponent(value) + expires + "; path=" + this.cookie_path;
    },

    readCookie: function(name) {
        name = name || this.identifier_cookie_name;
        var nameEQ = name + "=";
        var ca = document.cookie.split(';');
        for (var i = 0; i < ca.length; i++) {
            var c = ca[i];
            while (c.charAt(0) == ' ')
                c = c.substring(1, c.length);
            if (c.indexOf(nameEQ) == 0) {
                var value = c.substring(nameEQ.length, c.length);
                try {
                    return decodeURIComponent(value);
                } catch (e) {
                    return value;
                }
            }
        }
        return null;
    }
};
