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
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import hudson.model.User;
import hudson.plugins.openid.OpenIdTestService.IdProperty;
import hudson.tasks.Mailer;
import hudson.tasks.Mailer.UserProperty;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule.WebClient;

import static hudson.plugins.openid.OpenIdTestService.AX_EXTENSION;
import static hudson.plugins.openid.OpenIdTestService.SREG_EXTENSION;
import static hudson.plugins.openid.OpenIdTestService.TEAM_EXTENSION;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * @author Nirmal Jonnalagedda
 */
public class OpenIdAXEmailAttributesTest extends OpenIdTestCase {

    void _testEmailAttributes(String userName) throws Exception {
        WebClient wc = jr.createWebClient();

        OpenIdSsoSecurityRealm realm = new OpenIdSsoSecurityRealm(jr.openid.url);
        jr.jenkins.setSecurityRealm(realm);

        HtmlPage top = wc.goTo("");
        top = top.getAnchorByText("log in").click();

        User u = User.getById(userName, true);
        UserProperty up = u.getProperty(Mailer.UserProperty.class);

        assertTrue(up.hasExplicitlyConfiguredAddress());

        if (jr.openid.props.get(IdProperty.email) != null) {
            assertEquals(up.getAddress(), jr.openid.props.get(IdProperty.email));
        } else if (jr.openid.props.get(IdProperty.email2) != null) {
            assertEquals(up.getAddress(), jr.openid.props.get(IdProperty.email2));
        } else {
            assertEquals(up.getAddress(), jr.openid.props.get(IdProperty.email3));
        }
    }

    @Test
    public void testEmailWithAXExtensionWithAllSameEmailAttributes() throws Exception {
        jr.openid = new OpenIdTestService(
                jr.getServiceUrl(),
                getPropsAllSameEmails(),
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(SREG_EXTENSION, AX_EXTENSION, TEAM_EXTENSION));

        _testEmailAttributes(jr.openid.props.get(IdProperty.nick));
    }

    @Test
    public void testEmailWithAXExtensionWithAllDifferentEmailAttributes() throws Exception {
        jr.openid = new OpenIdTestService(
                jr.getServiceUrl(),
                getPropsAllDifferentEmails(),
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(SREG_EXTENSION, AX_EXTENSION, TEAM_EXTENSION));

        _testEmailAttributes(jr.openid.props.get(IdProperty.nick));
    }

    @Test
    public void testEmailWithAXExtensionWithAnyTwoDifferentEmailAttributes() throws Exception {
        jr.openid = new OpenIdTestService(
                jr.getServiceUrl(),
                getPropsWithAnyTwoDifferentEmails(),
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(SREG_EXTENSION, AX_EXTENSION, TEAM_EXTENSION));

        _testEmailAttributes(jr.openid.props.get(IdProperty.nick));
    }

    @Test
    public void testEmailWithAXExtensionWithAnyTwoSameEmailAttributes() throws Exception {
        jr.openid = new OpenIdTestService(
                jr.getServiceUrl(),
                getPropsWithAnyTwoSameEmails(),
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(SREG_EXTENSION, AX_EXTENSION, TEAM_EXTENSION));

        _testEmailAttributes(jr.openid.props.get(IdProperty.nick));
    }

    @Test
    public void testEmailWithAXExtensionWithOneEmailAttribute() throws Exception {
        jr.openid = new OpenIdTestService(
                jr.getServiceUrl(),
                getPropsWithOneEmail(),
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(SREG_EXTENSION, AX_EXTENSION, TEAM_EXTENSION));

        _testEmailAttributes(jr.openid.props.get(IdProperty.nick));
    }
}
