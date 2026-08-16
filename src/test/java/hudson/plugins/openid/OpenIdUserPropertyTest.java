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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.model.User;
import hudson.security.HudsonPrivateSecurityRealm;
import org.htmlunit.html.HtmlPage;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.JenkinsRule.WebClient;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

/**
 * @author Kohsuke Kawaguchi
 */
@WithJenkins
public class OpenIdUserPropertyTest {

    @Test
    public void testRoundtrip(JenkinsRule j) throws Exception {
        HudsonPrivateSecurityRealm realm = new HudsonPrivateSecurityRealm(false);
        j.jenkins.setSecurityRealm(realm);
        User u = realm.createAccount("alice", "alice");

        // submit empty config
        WebClient wc = j.createWebClient().login("alice", "alice");
        HtmlPage configure = wc.goTo("user/alice/account/");
        j.submit(configure.getFormByName("config"));

        OpenIdUserProperty p = u.getProperty(OpenIdUserProperty.class);
        assertTrue(p.getIdentifiers().isEmpty());

        // submit a non-empty config
        p.addIdentifier("http://me.cloudbees.com/");
        j.submit(configure.getFormByName("config"));
        p = u.getProperty(OpenIdUserProperty.class);
        assertTrue(p.has("http://me.cloudbees.com/"));
    }

    /**
     * Configuration roundtrip testing when the security realm doesn't support
     * OpenID.
     */
    @Test
    public void testDisabledRoundtrip(JenkinsRule j) throws Exception {
        User u = User.get("alice");
        u.save();

        // submit empty config
        WebClient wc = j.createWebClient();
        HtmlPage pg = wc.goTo("user/alice/account/");

        // should see no OpenID in the page
        assertFalse(pg.getWebResponse().getContentAsString().contains("OpenID"));

        j.submit(pg.getFormByName("config"));

        // should see No OpenID descriptor
        OpenIdUserProperty p = u.getProperty(OpenIdUserProperty.class);
        assertTrue(p == null || p.getIdentifiers().isEmpty());
    }
}
