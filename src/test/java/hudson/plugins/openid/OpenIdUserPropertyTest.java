/*
 * The MIT License
 *
 * Copyright (c) 2004-2009, Sun Microsystems, Inc., Kohsuke Kawaguchi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package hudson.plugins.openid;

import org.htmlunit.html.HtmlPage;
import hudson.model.User;
import hudson.security.HudsonPrivateSecurityRealm;
import org.jvnet.hudson.test.HudsonTestCase;

/**
 * @author Kohsuke Kawaguchi
 */
public class OpenIdUserPropertyTest extends HudsonTestCase {
    public void testRoundtrip() throws Exception {
        HudsonPrivateSecurityRealm realm = new HudsonPrivateSecurityRealm(false);
        hudson.setSecurityRealm(realm);
        User u = realm.createAccount("alice", "alice");

        // submit empty config
        WebClient wc = new WebClient().login("alice", "alice");
        HtmlPage configure = wc.goTo("user/alice/account/");
        submit(configure.getFormByName("config"));

        OpenIdUserProperty p = u.getProperty(OpenIdUserProperty.class);
        assertTrue(p.getIdentifiers().isEmpty());


        // submit a non-empty config
        p.addIdentifier("http://me.cloudbees.com/");
        submit(configure.getFormByName("config"));
        p = u.getProperty(OpenIdUserProperty.class);
        assertTrue(p.has("http://me.cloudbees.com/"));
    }

    /**
     * Configuration roundtrip testing when the security realm doesn't support
     * OpenID.
     */
    public void testDisabledRoundtrip() throws Exception {
        User u = User.get("alice");
        u.save();

        // submit empty config
        WebClient wc = createWebClient();
        HtmlPage pg = wc.goTo("user/alice/account/");

        // should see no OpenID in the page
        assertFalse(pg.getWebResponse().getContentAsString().contains("OpenID"));

        submit(pg.getFormByName("config"));

        // should see No OpenID descriptor
        OpenIdUserProperty p = u.getProperty(OpenIdUserProperty.class);
        assertTrue(p == null || p.getIdentifiers().isEmpty());
    }
}
