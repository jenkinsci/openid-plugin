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

import com.gargoylesoftware.htmlunit.Page;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;

import hudson.model.User;
import hudson.plugins.openid.OpenIdTestService.IdProperty;
import hudson.tasks.Mailer;
import hudson.tasks.Mailer.UserProperty;
import org.jvnet.hudson.test.JenkinsRule.WebClient;

import java.util.Map;

import static hudson.plugins.openid.OpenIdTestService.*;
import static org.junit.Assert.*;

/**
 * @author Nirmal Jonnalagedda
 */
public class OpenIdAXEmailAttributesTest extends OpenIdTestCase {

    void _testEmailAttributes(String userName) throws Exception {
        WebClient wc = jr.createWebClient();

        OpenIdSsoSecurityRealm realm = new OpenIdSsoSecurityRealm(openid.url);
        jr.jenkins.setSecurityRealm(realm);

        HtmlPage top = wc.goTo("");
        top = top.getAnchorByText("log in").click();
        
        User u = User.get(userName);
        UserProperty up = u.getProperty(Mailer.UserProperty.class);
        
        assertTrue(up.hasExplicitlyConfiguredAddress());
        
        if (openid.props.get(IdProperty.email) != null)
            assertEquals(up.getAddress(), openid.props.get(IdProperty.email));
        else if (openid.props.get(IdProperty.email2) != null)
            assertEquals(up.getAddress(), openid.props.get(IdProperty.email2));
        else
            assertEquals(up.getAddress(), openid.props.get(IdProperty.email3));
    }

    public void testEmailWithAXExtensionWithAllSameEmailAttributes() throws Exception {
        openid = new OpenIdTestService(
                getServiceUrl(),
                getPropsAllSameEmails(),
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(SREG_EXTENSION, AX_EXTENSION, TEAM_EXTENSION));
        
        _testEmailAttributes(openid.props.get(IdProperty.nick));
    }
    
    public void testEmailWithAXExtensionWithAllDifferentEmailAttributes() throws Exception {
        openid = new OpenIdTestService(
                getServiceUrl(),
                getPropsAllDifferentEmails(),
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(SREG_EXTENSION, AX_EXTENSION, TEAM_EXTENSION));

        _testEmailAttributes(openid.props.get(IdProperty.nick));
    }
    
    public void testEmailWithAXExtensionWithAnyTwoDifferentEmailAttributes() throws Exception {
        openid = new OpenIdTestService(
                getServiceUrl(),
                getPropsWithAnyTwoDifferentEmails(),
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(SREG_EXTENSION, AX_EXTENSION, TEAM_EXTENSION));

        _testEmailAttributes(openid.props.get(IdProperty.nick));
    }
    
    public void testEmailWithAXExtensionWithAnyTwoSameEmailAttributes() throws Exception {
        openid = new OpenIdTestService(
                getServiceUrl(),
                getPropsWithAnyTwoSameEmails(),
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(SREG_EXTENSION, AX_EXTENSION, TEAM_EXTENSION));

        _testEmailAttributes(openid.props.get(IdProperty.nick));
    }
    
    public void testEmailWithAXExtensionWithOneEmailAttribute() throws Exception {
        openid = new OpenIdTestService(
                getServiceUrl(),
                getPropsWithOneEmail(),
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(SREG_EXTENSION, AX_EXTENSION, TEAM_EXTENSION));

        _testEmailAttributes(openid.props.get(IdProperty.nick));
    }
}