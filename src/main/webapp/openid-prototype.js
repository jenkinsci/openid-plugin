/*
 * Simple OpenID Plugin
 * http://code.google.com/p/openid-selector/
 * This code is licensed under the New BSD License.
*/

/* jslint browser: true */
/* global $, jQuery */

var openid = {
    version: '1.3-beta1', // version constant
    demo: false,
    demo_text: null,
    cookie_expires: 6 * 30, // 6 months.
    cookie_name: 'openid_provider',
    cookie_path: '/',

    img_path: 'images/',
    locale: null, // is set in openid-<locale>.js
    sprite: null, // usually equals to locale, is set in
    // openid-<locale>.js
    signin_text: null, // text on submit button on the form
    all_small: false, // output large providers w/ small icons
    no_sprite: false, // don't use sprite image
    image_title: '{provider}', // for image title

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
        var providers = this.providers;
        var providers_large;
        var providers_small;

        Object.extend(providers, providers_large);
        Object.extend(providers, providers_small);
        var openid_btns = $('openid_btns');
        this.input_id = input_id;
        $('openid_choice').setStyle({
            display: 'block'
        });
        $('openid_input_area').innerHTML = "";
        var i = 0;
        // add box for each provider
        var html = '';
        for (id in providers_large) {
            if (providers_large.hasOwnProperty(id)) {
                html += this.getBoxHTML(id, providers_large[id], (this.all_small ? 'small' : 'large'), i++);
            }
        }
        if (providers_small) {
            html += '<br/>';
            for (id in providers_small) {
                if (providers_small.hasOwnProperty(id)) {
                    html += this.getBoxHTML(id, providers_small[id], 'small', i++);
                }
            }
        }
        openid_btns.innerHTML = html;
        $('openid_form').onsubmit = this.onsubmit;
        var box_id = this.readCookie();
        if (box_id) {
            this.signin(box_id, true);
        }
    },

    /**
     * @return {String}
     */
    getBoxHTML: function(box_id, provider, box_size, index) {
        if (this.no_sprite) {
            var image_ext = box_size == 'small' ? '.ico.gif' : '.gif';
            return '<a title="' + this.image_title.replace('{provider}', provider["name"]) + '" href="javascript:openid.signin(\'' + box_id + '\');"' +
                ' style="background: #FFF url(' + this.img_path + '../images.' + box_size + '/' + box_id + image_ext + ') no-repeat center center" ' +
                'class="' + box_id + ' openid_' + box_size + '_btn"></a>';
        }
        var x = box_size == 'small' ? -index * 24 : -index * 100;
        var y = box_size == 'small' ? -60 : 0;
        return '<a title="' + this.image_title.replace('{provider}', provider["name"]) + '" href="javascript:openid.signin(\'' + box_id + '\');"' +
            ' style="background: #FFF url(' + this.img_path + 'openid-providers-' + this.sprite + '.png); background-position: ' + x + 'px ' + y + 'px" ' +
            'class="' + box_id + ' openid_' + box_size + '_btn"></a>';
    },

    /**
     * Provider image click
     *
     * @return {void}
     */
    signin: function(box_id, onload) {
        var provider = this.providers[box_id];
        if (!provider) {
            return;
        }
        this.highlight(box_id);
        this.setCookie(box_id);
        this.provider_id = box_id;
        this.provider_url = provider['url'];
        // prompt user for input?
        if (provider['label']) {
            this.useInputBox(provider);
        } else {
            $('openid_input_area').innerHTML = '';
            if (!onload) {
                this.submit();
            }
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
        }
        if (openid.demo) {
            alert(openid.demo_text + "\r\n" + document.getElementById(openid.input_id).value);
            return false;
        }
        if (url && url.indexOf("javascript:") == 0) {
            url = url.substr("javascript:".length);
            eval(url);
            return false;
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

    /**
     * @return {Void}
     */
    highlight: function(box_id) {
        // remove previous highlight.
        var highlight = $('openid_highlight');
        if (highlight) {
            fc = highlight.firstChild;
            highlight.parentNode.replaceChild(fc, highlight);
        }
        // add new highlight.
        var box = $$('.' + box_id)[0];
        var wrapper = document.createElement('div');
        wrapper.id = 'openid_highlight';
        box.parentNode.replaceChild(wrapper, box);
        wrapper.appendChild(box);
    },

    setCookie: function(value) {
        var date = new Date();
        date.setTime(date.getTime() + (this.cookie_expires * 24 * 60 * 60 * 1000));
        var expires = "; expires=" + date.toGMTString();
        document.cookie = this.cookie_name + "=" + value + expires + "; path=" + this.cookie_path;
    },

    readCookie: function() {
        var nameEQ = this.cookie_name + "=";
        var ca = document.cookie.split(';');
        for (var i = 0; i < ca.length; i++) {
            var c = ca[i];
            while (c.charAt(0) == ' ')
                c = c.substring(1, c.length);
            if (c.indexOf(nameEQ) == 0)
                return c.substring(nameEQ.length, c.length);
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
            value = 'http://';
            style = 'background: #FFF url(' + this.img_path + 'openid-inputicon.gif) no-repeat scroll 0 50%; padding-left:18px;';
        }
        html += '<input id="' + id + '" type="text" style="' + style + '" name="' + id + '" value="' + value + '" />' +
            '<input id="openid_submit" type="submit" value="' + this.signin_text + '"/>';
        input_area.innerHTML = html;
        $('openid_submit').onclick = this.submit;
        $(id).focus();
    },

    setDemoMode: function(demoMode) {
        this.demo = demoMode;
    }
};
