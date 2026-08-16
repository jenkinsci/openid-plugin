/*
 * Simple OpenID Plugin
 * https://code.google.com/p/openid-selector/
 * This code is licensed under the New BSD License.
*/

/*
 * OpenID 2.0 is deprecated: the major providers (Google, Yahoo, AOL,
 * MyOpenID, LiveJournal, WordPress, Blogger, Verisign, ClaimID, ClickPass)
 * have all shut down their endpoints. Only the custom-identifier entry
 * remains, which works with self-hosted and enterprise OpenID providers.
 */

var providers_large = {
    openid: {
        name: 'OpenID',
        label: 'Enter your OpenID.',
        url: null
    }
};

var providers_small = {};

openid.locale = 'en';
openid.sprite = 'en'; // reused in german& japan localization
openid.demo_text = 'In client demo mode. Normally would have submitted OpenID:';
openid.signin_text = 'Sign-In';
openid.image_title = 'log in with {provider}';
