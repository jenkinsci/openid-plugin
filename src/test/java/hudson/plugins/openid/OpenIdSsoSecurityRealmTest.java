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
import hudson.ProxyConfiguration;
import hudson.model.User;
import hudson.plugins.openid.OpenIdTestService.IdProperty;

import java.util.Collections;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Callable;

import org.acegisecurity.Authentication;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.JenkinsRule.WebClient;
import org.openid4java.discovery.DiscoveryException;
import org.openid4java.util.HttpClientFactory;

import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;

import static org.junit.Assert.*;
import static org.hamcrest.CoreMatchers.containsString;

/**
 * @author Paul Sandoz
 */
public class OpenIdSsoSecurityRealmTest extends OpenIdTestCase {

    private static final String FAKE_PROXY_PASSWORD = "mrwayne";
    private static final String FAKE_PROXY_USER_NAME = "thebutler";
    private static final int FAKE_PROXY_PORT_ALTERNATIVE = 4321;
    private static final int FAKE_JENKINS_PROXY_PORT = 1234;
    private static final String FAKE_PROXY_NAME = "fakeproxy.jenkins-ci.org";

    @Rule
    public OpenIdRule jr = new SsoSecurityRealmTestRule();

    void _testLogin(String userName) throws Exception {
        WebClient wc = jr.createWebClient();

        OpenIdSsoSecurityRealm realm = new OpenIdSsoSecurityRealm(jr.openid.url);
        jr.jenkins.setSecurityRealm(realm);

        HtmlPage top = wc.goTo("");
        top = top.getAnchorByText("log in").click();

        assertNotNull(top.getAnchorByHref("/jenkins/logout"));

        Authentication a = wc.executeOnServer(() -> SecurityContextHolder.getContext().getAuthentication());
        assertTrue(a instanceof UsernamePasswordAuthenticationToken);
        for (String team : jr.openid.teams) {
            assertTrue(isTeamAGrantedAuthority(a.getAuthorities(), team));
        }

        String effectiveId = User.CanonicalIdResolver.resolve(userName, Collections.emptyMap());
        User u = User.getById(effectiveId, false);
        assertNotNull(u);
        assertNotNull(top.getAnchorByHref("/jenkins/user/" + u.getId().toLowerCase(Locale.ENGLISH)));
        OpenIdUserProperty p = u.getProperty(OpenIdUserProperty.class);
        assertNotNull(p);

        assertEquals(1, p.getIdentifiers().size());
        assertThat(p.getIdentifiers().iterator().next(), containsString(jr.openid.getUserIdentity()));
    }

    private boolean isTeamAGrantedAuthority(GrantedAuthority[] gas, String team) {
        for (GrantedAuthority ga : gas) {
            if (team.equals(ga.getAuthority())) {
                return true;
            }
        }

        return false;
    }

    @Test
    public void testLoginWithAllExtensions() throws Exception {
        jr.openid = new OpenIdTestService(
                jr.getServiceUrl(),
                getProps(),
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(SREG_EXTENSION, AX_EXTENSION, TEAM_EXTENSION));

        _testLogin(jr.openid.props.get(IdProperty.nick));
    }

    @Test
    public void testLoginWithWithoutAXExtension() throws Exception {
        jr.openid = new OpenIdTestService(
                jr.getServiceUrl(),
                getProps(),
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(SREG_EXTENSION, TEAM_EXTENSION));

        _testLogin(jr.openid.props.get(IdProperty.nick));
    }

    @Test
    public void testLoginWithWithoutAXExtensionAndNick() throws Exception {
        Map<IdProperty,String> props = getProps();
        props.remove(IdProperty.nick);
        jr.openid = new OpenIdTestService(
                jr.getServiceUrl(),
                props,
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(SREG_EXTENSION, TEAM_EXTENSION));

        _testLogin(jr.openid.props.get(IdProperty.email));
    }

    @Test
    public void testLoginWithWithoutAXExtensionAndNickAndEmail() throws Exception {
        Map<OpenIdTestService.IdProperty,String> props = getProps();
        props.put(OpenIdTestService.IdProperty.email2, props.get(OpenIdTestService.IdProperty.email)); //TODO: better define how to get UserIdentity
        props.remove(OpenIdTestService.IdProperty.nick);
        props.remove(OpenIdTestService.IdProperty.email);
        jr.openid = new OpenIdTestService(
                jr.getServiceUrl(),
                props,
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(OpenIdTestService.SREG_EXTENSION, OpenIdTestService.TEAM_EXTENSION));

        _testLogin(jr.openid.getUserIdentity());
    }

    @Test
    public void testLoginWithWithoutSRegExtension() throws Exception {
        jr.openid = new OpenIdTestService(
                jr.getServiceUrl(),
                getProps(),
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(AX_EXTENSION, TEAM_EXTENSION));

        _testLogin(jr.openid.props.get(IdProperty.email));
    }

    @Test
    public void testLoginWithWithoutSRegExtensionAndEmailAddress() throws Exception {
        Map<OpenIdTestService.IdProperty,String> props = getProps();
        props.put(OpenIdTestService.IdProperty.email2, props.get(OpenIdTestService.IdProperty.email)); //TODO: better define how to get UserIdentity
        props.remove(OpenIdTestService.IdProperty.email);
        jr.openid = new OpenIdTestService(
                jr.getServiceUrl(),
                props,
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(OpenIdTestService.AX_EXTENSION, OpenIdTestService.TEAM_EXTENSION));

        _testLogin(jr.openid.props.get(IdProperty.email2));
    }

    @Test
    public void testProxyInformationAvailableForCreateManager()
            throws Exception {
        jr.openid = new OpenIdTestService(jr.getServiceUrl(), getProps(),
                Sets.newHashSet("foo", "bar"), Lists.newArrayList(
                        SREG_EXTENSION, AX_EXTENSION, TEAM_EXTENSION));
        jr.jenkins.proxy = new ProxyConfiguration(FAKE_PROXY_NAME,
                FAKE_JENKINS_PROXY_PORT);

        try {
            OpenIdSsoSecurityRealm realm = new OpenIdSsoSecurityRealm(jr.openid.url);
            realm.createManager();
        } catch (DiscoveryException e) {
            // This is expected since the proxy is fake. Hence, discovery will
            // not be possible
        }

        assertEquals(FAKE_PROXY_NAME, HttpClientFactory.getProxyProperties()
                .getProxyHostName());
        assertEquals(FAKE_JENKINS_PROXY_PORT, HttpClientFactory
                .getProxyProperties().getProxyPort());
    }

    @Test
    public void testProxyInformationAvailableForDiscoverNoCredentials()
            throws Exception {
        jr.openid = new OpenIdTestService(jr.getServiceUrl(), getProps(),
                Sets.newHashSet("foo", "bar"), Lists.newArrayList(
                        SREG_EXTENSION, AX_EXTENSION, TEAM_EXTENSION));

        jr.jenkins.proxy = new ProxyConfiguration(FAKE_PROXY_NAME,
                FAKE_JENKINS_PROXY_PORT);
        try {
            new OpenIdSsoSecurityRealm(jr.openid.url);
        } catch (DiscoveryException e) {
            // This is expected since the proxy is fake. Hence, discovery will
            // not be possible
        }

        assertEquals(FAKE_PROXY_NAME, HttpClientFactory.getProxyProperties()
                .getProxyHostName());
        assertEquals(FAKE_JENKINS_PROXY_PORT, HttpClientFactory
                .getProxyProperties().getProxyPort());
        // The openid4java ProxyProperties class returns a default value of
        // anonymous if userName
        // or password is null or empty string
        assertEquals("anonymous", HttpClientFactory.getProxyProperties()
                .getUserName());
        assertEquals("anonymous", HttpClientFactory.getProxyProperties()
                .getPassword());
    }

    @Test
    public void testProxyInformationAvailableForDiscoverWithCredentials()
            throws Exception {
        jr.openid = new OpenIdTestService(jr.getServiceUrl(), getProps(),
                Sets.newHashSet("foo", "bar"), Lists.newArrayList(
                        SREG_EXTENSION, AX_EXTENSION, TEAM_EXTENSION));

        jr.jenkins.proxy = new ProxyConfiguration(FAKE_PROXY_NAME,
                FAKE_PROXY_PORT_ALTERNATIVE, FAKE_PROXY_USER_NAME,
                FAKE_PROXY_PASSWORD);
        try {
            new OpenIdSsoSecurityRealm(jr.openid.url);
        } catch (DiscoveryException e) {
            // This is expected since the proxy is fake. Hence, discovery will
            // not be possible
        }

        assertEquals(FAKE_PROXY_NAME, HttpClientFactory.getProxyProperties()
                .getProxyHostName());
        assertEquals(FAKE_PROXY_PORT_ALTERNATIVE, HttpClientFactory
                .getProxyProperties().getProxyPort());
        assertEquals(FAKE_PROXY_USER_NAME, HttpClientFactory
                .getProxyProperties().getUserName());
        assertEquals(FAKE_PROXY_PASSWORD, HttpClientFactory
                .getProxyProperties().getPassword());
    }

    public static class SsoSecurityRealmTestRule extends OpenIdTestCase.OpenIdRule {
        @Before
        public void before() throws Throwable {
            super.before();

            HttpClientFactory.setProxyProperties(null);
        } 
    }
}
