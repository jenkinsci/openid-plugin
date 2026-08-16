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

import static hudson.plugins.openid.OpenIdTestService.AX_EXTENSION;
import static hudson.plugins.openid.OpenIdTestService.SREG_EXTENSION;
import static hudson.plugins.openid.OpenIdTestService.TEAM_EXTENSION;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import hudson.model.User;
import hudson.plugins.openid.OpenIdTestService.IdProperty;
import hudson.tasks.Mailer;
import hudson.tasks.Mailer.UserProperty;
import org.htmlunit.html.HtmlPage;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule.WebClient;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

/**
 * @author Nirmal Jonnalagedda
 */
@WithJenkins
public class OpenIdAXEmailAttributesTest extends OpenIdTestCase {

    void _testEmailAttributes(JenkinsRule j, OpenIdTestService openid, String userName) throws Exception {
        WebClient wc = j.createWebClient();

        OpenIdSsoSecurityRealm realm = new OpenIdSsoSecurityRealm(openid.url);
        j.jenkins.setSecurityRealm(realm);

        HtmlPage top = wc.goTo("");
        top = top.getAnchorByText("log in").click();

        User u = User.getById(userName, true);
        UserProperty up = u.getProperty(Mailer.UserProperty.class);

        assertTrue(up.hasExplicitlyConfiguredAddress());

        if (openid.props.get(IdProperty.email) != null) {
            assertEquals(openid.props.get(IdProperty.email), up.getAddress());
        } else if (openid.props.get(IdProperty.email2) != null) {
            assertEquals(openid.props.get(IdProperty.email2), up.getAddress());
        } else {
            assertEquals(openid.props.get(IdProperty.email3), up.getAddress());
        }
    }

    @Test
    public void testEmailWithAXExtensionWithAllSameEmailAttributes(JenkinsRule j) throws Exception {
        OpenIdTestService openid = createOpenIdServer(
                j,
                getPropsAllSameEmails(),
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(SREG_EXTENSION, AX_EXTENSION, TEAM_EXTENSION));

        _testEmailAttributes(j, openid, openid.props.get(IdProperty.nick));
    }

    @Test
    public void testEmailWithAXExtensionWithAllDifferentEmailAttributes(JenkinsRule j) throws Exception {
        OpenIdTestService openid = createOpenIdServer(
                j,
                getPropsAllDifferentEmails(),
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(SREG_EXTENSION, AX_EXTENSION, TEAM_EXTENSION));

        _testEmailAttributes(j, openid, openid.props.get(IdProperty.nick));
    }

    @Test
    public void testEmailWithAXExtensionWithAnyTwoDifferentEmailAttributes(JenkinsRule j) throws Exception {
        OpenIdTestService openid = createOpenIdServer(
                j,
                getPropsWithAnyTwoDifferentEmails(),
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(SREG_EXTENSION, AX_EXTENSION, TEAM_EXTENSION));

        _testEmailAttributes(j, openid, openid.props.get(IdProperty.nick));
    }

    @Test
    public void testEmailWithAXExtensionWithAnyTwoSameEmailAttributes(JenkinsRule j) throws Exception {
        OpenIdTestService openid = createOpenIdServer(
                j,
                getPropsWithAnyTwoSameEmails(),
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(SREG_EXTENSION, AX_EXTENSION, TEAM_EXTENSION));

        _testEmailAttributes(j, openid, openid.props.get(IdProperty.nick));
    }

    @Test
    public void testEmailWithAXExtensionWithOneEmailAttribute(JenkinsRule j) throws Exception {
        OpenIdTestService openid = createOpenIdServer(
                j,
                getPropsWithOneEmail(),
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(SREG_EXTENSION, AX_EXTENSION, TEAM_EXTENSION));

        _testEmailAttributes(j, openid, openid.props.get(IdProperty.nick));
    }
}
