/*
 * Simple OpenID Plugin
 * https://code.google.com/p/openid-selector/
 * This code is licensed under the New BSD License.
*/

/* jslint browser: true */
/* global $, jQuery */

/*
 * Modern Jenkins no longer bundles Prototype.js, but this file still relies on
 * a few of its helpers. Provide minimal replacements so the login form works.
 */
if (typeof Object.extend !== 'function') {
    Object.extend = function(destination, source) {
        for (var key in source) {
            if (Object.prototype.hasOwnProperty.call(source, key)) {
                destination[key] = source[key];
            }
        }
        return destination;
    };
}
if (typeof $ !== 'function') {
    $ = function(id) {
        return document.getElementById(id);
    };
}
if (typeof $$ !== 'function') {
    $$ = function(selector) {
        return document.querySelectorAll(selector);
    };
}

var openid = {
    version: '1.3-beta1', // version constant
    demo: false,
    demo_text: null,
    cookie_expires: 6 * 30, // 6 months.
    identifier_cookie_name: 'openid_identifier',
    cookie_path: '/',

    img_path: 'images/',
    signin_text: null, // text on submit button on the form

    input_id: null,
    provider_url: null,
    provider_id: null,

    providers: {},

    /**
     * Class constructor
     *
     * @return {Void}
     */
    init: function(input_id) {
        "use strict";
        Object.extend(this.providers, providers_large);
        Object.extend(this.providers, providers_small);
        this.input_id = input_id;

        // All hosted OpenID providers have shut down, so the only remaining
        // option is a custom OpenID identifier. Show its input directly instead
        // of rendering a provider selector.
        $('openid_form').onsubmit = this.onsubmit;
        this.provider_id = 'openid';
        this.provider_url = null;
        this.useInputBox(this.providers['openid']);

        var identifier = this.readCookie(this.identifier_cookie_name);
        if (identifier) {
            this.restoreIdentifier(identifier);
        }
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
        var url = openid.provider_url;
        var username_field = $('openid_username');
        var username = username_field ? $('openid_username').value : '';
        if (url) {
            url = url.replace('{username}', username);
            openid.setOpenIdUrl(url);
        } else {
            // The "OpenID" provider accepts a full identifier typed by the
            // user, so read it directly from the input box.
            var input = document.getElementById(openid.input_id);
            if (input) {
                url = input.value;
            }
        }
        if (openid.demo) {
            alert(openid.demo_text + "\r\n" + document.getElementById(openid.input_id).value);
            return false;
        }
        if (url && url != 'https://') {
            openid.setCookie(url, openid.identifier_cookie_name);
        }
        return true;
    },

    /**
     * @return {Void}
     */
    setOpenIdUrl: function(url) {
        var hidden = document.getElementById(this.input_id);
        if (hidden != null) {
            hidden.value = url;
        } else {
            $('openid_form').innerHTML += ('<input type="hidden" id="' + this.input_id + '" name="' + this.input_id + '" value="' + url + '"/>');
        }
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
    },

    /**
     * @return {Void}
     */
    useInputBox: function(provider) {
        var input_area = $('openid_input_area');
        var html = '';
        var id = 'openid_username';
        var value = '';
        var label = provider['label'];
        var style = '';
        if (label) {
            html = '<p>' + label + '</p>';
        }
        if (provider['name'] == 'OpenID') {
            id = this.input_id;
            value = 'https://';
            style = 'background: #FFF url(' + this.img_path + 'openid-inputicon.gif) no-repeat scroll 0 50%; padding-left:18px;';
        }
        html += '<input id="' + id + '" type="text" class="jenkins-input" style="' + style + '" name="' + id + '" value="' + value + '" />' +
            '<button id="openid_submit" type="submit" class="jenkins-button jenkins-button--primary">' + this.signin_text + '</button>';
        input_area.innerHTML = html;
        $('openid_submit').onclick = this.submit;
        $(id).focus();
    },

    setDemoMode: function(demoMode) {
        this.demo = demoMode;
    }
};
