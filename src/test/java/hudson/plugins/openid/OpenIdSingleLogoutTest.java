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

import java.util.Map;

import static hudson.plugins.openid.OpenIdTestService.*;

/**
 * @author Nirmal Jonnalagedda
 */
public class OpenIdSingleLogoutTest extends OpenIdTestCase {

    void _testLogout() throws Exception {
        WebClient wc = new WebClient();
        
        OpenIdSsoSecurityRealm realm = new OpenIdSsoSecurityRealm(openid.url);
        hudson.setSecurityRealm(realm);
        
        Page login = wc.goTo("");
        final HtmlPage loggedIn = ((HtmlPage) login).getAnchorByText("log in").click();
        
        assertNotNull(loggedIn.getAnchorByHref("/logout"));
        
        login = wc.goTo("/securityRealm/logoutImage", "image/gif");
        final Page loggedOut = loggedIn.refresh();
        
        assertNotNull(((HtmlPage) loggedOut).getAnchorByText("log in"));
    }
    
    public void testLogoutWithAllExtensions() throws Exception {
        openid = new OpenIdTestService(
                getServiceUrl(),
                getProps(),
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(SREG_EXTENSION, AX_EXTENSION, TEAM_EXTENSION));

        _testLogout();
    }
    
    public void testLogoutWithWithoutAXExtension() throws Exception {
        openid = new OpenIdTestService(
                getServiceUrl(),
                getProps(),
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(SREG_EXTENSION, TEAM_EXTENSION));

        _testLogout();
    }
    
    public void testLogoutWithWithoutAXExtensionAndNick() throws Exception {
        Map<IdProperty,String> props = getProps();
        props.remove(IdProperty.nick);
        openid = new OpenIdTestService(
                getServiceUrl(),
                props,
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(SREG_EXTENSION, TEAM_EXTENSION));

        _testLogout();
    }
    
    public void testLogoutWithWithoutAXExtensionAndNickAndEmail() throws Exception {
        Map<OpenIdTestService.IdProperty,String> props = getProps();
        props.remove(OpenIdTestService.IdProperty.nick);
        props.remove(OpenIdTestService.IdProperty.email);
        openid = new OpenIdTestService(
                getServiceUrl(),
                props,
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(OpenIdTestService.SREG_EXTENSION, OpenIdTestService.TEAM_EXTENSION));

        _testLogout();
    }
    
    public void testLogoutWithWithoutSRegExtension() throws Exception {
        openid = new OpenIdTestService(
                getServiceUrl(),
                getProps(),
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(AX_EXTENSION, TEAM_EXTENSION));

        _testLogout();
    }
    
    public void testLogoutWithWithoutSRegExtensionAndEmailAddress() throws Exception {
        Map<OpenIdTestService.IdProperty,String> props = getProps();
        props.remove(OpenIdTestService.IdProperty.email);
        openid = new OpenIdTestService(
                getServiceUrl(),
                props,
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(OpenIdTestService.AX_EXTENSION, OpenIdTestService.TEAM_EXTENSION));

        _testLogout();
    }
    
}