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
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import hudson.model.User;
import java.io.IOException;
import java.util.List;
import jenkins.model.Jenkins;
import org.htmlunit.ElementNotFoundException;
import org.htmlunit.html.HtmlForm;
import org.htmlunit.html.HtmlPage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.JenkinsRule.DummySecurityRealm;
import org.jvnet.hudson.test.JenkinsRule.WebClient;
import org.jvnet.hudson.test.MockAuthorizationStrategy;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

/**
 * @author Paul Sandoz
 */
@WithJenkins
public class OpenIdLoginServiceTest extends OpenIdTestCase {
    private DummySecurityRealm realm;

    @BeforeEach
    public void setUp(JenkinsRule j) {
        realm = j.createDummySecurityRealm();
        j.jenkins
                .getDescriptorByType(OpenIdLoginService.GlobalConfigurationImpl.class)
                .setEnabled(true);
    }

    @Issue("JENKINS-9792")
    @Test
    @Disabled("Failing manually")
    public void testLoginWithoutReadAccess(JenkinsRule j) throws Exception {
        OpenIdTestService openid = createServer(j);

        j.jenkins.setSecurityRealm(realm);
        realm.loadUserByUsername("aliceW");
        User u = User.getById("aliceW", true);
        associateUserWithOpenId(j, openid, u);

        // configure Jenkins to allow no access at all without login
        j.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy()
                .grant(Jenkins.ADMINISTER)
                .everywhere()
                .to("authenticated"));

        // try to login
        login(j, openid, j.createWebClient());
    }

    @Test
    @Disabled("Failing manually")
    public void testAssociateThenLogoutThenLogInWithOpenID(JenkinsRule j) throws Exception {
        OpenIdTestService openid = createServer(j);
        j.jenkins.setSecurityRealm(realm);
        realm.loadUserByUsername("aliceW");
        User u = User.getById("aliceW", true);
        associateUserWithOpenId(j, openid, u);

        // Re-login
        login(j, openid, j.createWebClient());
    }

    /**
     * Associates the OpenID identity of the user with {@link #realm}.
     */
    private void associateUserWithOpenId(JenkinsRule j, OpenIdTestService openid, User u) throws Exception {
        WebClient wc = j.createWebClient().login(u.getId(), u.getId() /*assumes password==name*/);

        // Associate an OpenID with an existing user
        wc.goTo("federatedLoginService/openid/startAssociate?openid=" + openid.url);
        OpenIdUserProperty p = u.getProperty(OpenIdUserProperty.class);
        assertEquals(1, p.getIdentifiers().size());
        assertEquals(openid.getUserIdentity(), p.getIdentifiers().iterator().next());
    }

    @Test
    @Disabled("Failing manually")
    public void testLogInWithOpenIDAndSignUp(JenkinsRule j) throws Exception {
        OpenIdTestService openid = createServer(j);

        realm = j.createDummySecurityRealm();
        j.jenkins.setSecurityRealm(realm);

        WebClient wc = j.createWebClient();
        // Workaround failing ajax requests to build queue
        wc.getOptions().setThrowExceptionOnScriptError(false);

        // Login with OpenID as an unregistered user
        HtmlPage login = wc.goTo("federatedLoginService/openid/login?from=/");
        HtmlForm loginForm = getFormById(login, "openid_form");
        loginForm.getInputByName("openid").setValue(openid.url);
        HtmlPage signUp = j.submit(loginForm);

        // Sign up user
        HtmlForm signUpForm = getFormByAction(signUp, "/securityRealm/createAccountWithFederatedIdentity");
        signUpForm.getInputByName("password1").setValue("x");
        signUpForm.getInputByName("password2").setValue("x");
        HtmlPage loggedIn = j.submit(signUpForm);

        assertNotNull(loggedIn.getAnchorByHref("/logout"));
        assertNotNull(loggedIn.getAnchorByHref("/user/aliceW"));

        wc.goTo("logout");

        // Re-login
        login(j, openid, wc);
    }

    /**
     * Creates a OpenID server.
     */
    private OpenIdTestService createServer(JenkinsRule j) throws IOException {
        return createOpenIdServer(
                j,
                getProps(),
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(SREG_EXTENSION, AX_EXTENSION, TEAM_EXTENSION));
    }

    private void login(JenkinsRule j, OpenIdTestService openid, WebClient wc) throws Exception {
        HtmlPage login = wc.goTo("federatedLoginService/openid/login?from=/");
        HtmlForm loginForm = getFormById(login, "openid_form");
        loginForm.getInputByName("openid").setValue(openid.url);
        HtmlPage loggedIn = j.submit(loginForm);

        assertNotNull(loggedIn.getAnchorByHref("/jenkins/logout"));
        assertNotNull(loggedIn.getAnchorByHref("/jenkins/user/aliceW"));
    }

    private HtmlForm getFormById(HtmlPage p, String id) throws ElementNotFoundException {
        return getFormByAttribute(p, "id", id);
    }

    private HtmlForm getFormByAction(HtmlPage p, String action) throws ElementNotFoundException {
        return getFormByAttribute(p, "action", action);
    }

    private HtmlForm getFormByAttribute(HtmlPage p, String name, String value) throws ElementNotFoundException {
        final List<HtmlForm> forms = p.getDocumentElement().getElementsByAttribute("form", name, value);
        if (forms.size() == 0) {
            throw new ElementNotFoundException("form", name, value);
        }
        return forms.get(0);
    }
}
