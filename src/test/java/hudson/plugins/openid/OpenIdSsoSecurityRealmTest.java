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

import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import hudson.model.User;
import org.acegisecurity.Authentication;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.jvnet.hudson.test.HudsonTestCase;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.Callable;

import static hudson.plugins.openid.OpenIdTestService.*;

/**
 * @author Paul Sandoz
 */
public class OpenIdSsoSecurityRealmTest extends OpenIdTestCase {

    void _testLogin(String userName) throws Exception {
        WebClient wc = new WebClient();

        OpenIdSsoSecurityRealm realm = new OpenIdSsoSecurityRealm(openid.url);
        hudson.setSecurityRealm(realm);

        HtmlPage top = wc.goTo("");
        top = top.getAnchorByText("log in").click();

        assertNotNull(top.getAnchorByHref("/logout"));

        assertNotNull(top.getAnchorByHref("/user/" + userName));

        Authentication a = wc.executeOnServer(new Callable<Authentication>() {
            public Authentication call() throws Exception {
                return SecurityContextHolder.getContext().getAuthentication();
            }
        });
        assertTrue(a instanceof UsernamePasswordAuthenticationToken);
        for (String team : openid.teams) {
            assertTrue(isTeamAGrantedAuthority(a.getAuthorities(), team));
        }

        User u = User.get(userName);
        assertNotNull(u);
        OpenIdUserProperty p = u.getProperty(OpenIdUserProperty.class);
        assertNotNull(p);

        assertEquals(1, p.getIdentifiers().size());
        assertEquals(openid.getUserIdentity(), p.getIdentifiers().iterator().next());
    }

    private boolean isTeamAGrantedAuthority(GrantedAuthority[] gas, String team) {
        for (GrantedAuthority ga : gas) {
            if (team.equals(ga.getAuthority())) return true;
        }

        return false;
    }

    public void testLoginWithAllExtensions() throws Exception {
        openid = new OpenIdTestService(
                getServiceUrl(),
                getProps(),
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(SREG_EXTENSION, AX_EXTENSION, TEAM_EXTENSION));

        _testLogin(openid.props.get(IdProperty.nick));
    }

    public void testLoginWithWithoutAXExtension() throws Exception {
        openid = new OpenIdTestService(
                getServiceUrl(),
                getProps(),
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(SREG_EXTENSION, TEAM_EXTENSION));

        _testLogin(openid.props.get(IdProperty.nick));
    }

    public void testLoginWithWithoutAXExtensionAndNick() throws Exception {
        Map<IdProperty,String> props = getProps();
        props.remove(IdProperty.nick);
        openid = new OpenIdTestService(
                getServiceUrl(),
                props,
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(SREG_EXTENSION, TEAM_EXTENSION));

        _testLogin(openid.props.get(IdProperty.email));
    }

    public void testLoginWithWithoutAXExtensionAndNickAndEmail() throws Exception {
        Map<OpenIdTestService.IdProperty,String> props = getProps();
        props.remove(OpenIdTestService.IdProperty.nick);
        props.remove(OpenIdTestService.IdProperty.email);
        openid = new OpenIdTestService(
                getServiceUrl(),
                props,
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(OpenIdTestService.SREG_EXTENSION, OpenIdTestService.TEAM_EXTENSION));

        _testLogin(openid.getUserIdentity());
    }

    public void testLoginWithWithoutSRegExtension() throws Exception {
        openid = new OpenIdTestService(
                getServiceUrl(),
                getProps(),
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(AX_EXTENSION, TEAM_EXTENSION));

        _testLogin(openid.props.get(IdProperty.email));
    }


    public void testLoginWithWithoutSRegExtensionAndEmailAddress() throws Exception {
        Map<OpenIdTestService.IdProperty,String> props = getProps();
        props.remove(OpenIdTestService.IdProperty.email);
        openid = new OpenIdTestService(
                getServiceUrl(),
                props,
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(OpenIdTestService.AX_EXTENSION, OpenIdTestService.TEAM_EXTENSION));

        _testLogin(openid.getUserIdentity());
    }
}