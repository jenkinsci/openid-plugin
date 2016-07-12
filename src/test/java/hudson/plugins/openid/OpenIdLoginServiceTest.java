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

import com.gargoylesoftware.htmlunit.ElementNotFoundException;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlElement;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import hudson.model.User;
import jenkins.model.Jenkins;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.JenkinsRule.DummySecurityRealm;
import org.jvnet.hudson.test.JenkinsRule.WebClient;
import org.jvnet.hudson.test.MockAuthorizationStrategy;

import java.io.IOException;
import java.util.List;

import static hudson.plugins.openid.OpenIdTestService.*;
import static org.junit.Assert.*;

/**
 * @author Paul Sandoz
 */
public class OpenIdLoginServiceTest extends OpenIdTestCase {
    public static DummySecurityRealm realm;

    @Rule
    public JenkinsRule jr = new LoginServiceTestRule();

    @Issue(9792)
    @Test
    public void testLoginWithoutReadAccess() throws Exception {
        openid = createServer();

        jr.jenkins.setSecurityRealm(realm);
        realm.loadUserByUsername("aliceW");
        User u = User.get("aliceW");
        associateUserWithOpenId(u);

        // configure Jenkins to allow no access at all without login
        jr.jenkins.setAuthorizationStrategy(new MockAuthorizationStrategy().
            grant(Jenkins.ADMINISTER).everywhere().to("authenticated"));

        // try to login
        login(jr.createWebClient());
    }

    @Test
    public void testAssociateThenLogoutThenLogInWithOpenID() throws Exception {
        openid = createServer();
        jr.jenkins.setSecurityRealm(realm);
        realm.loadUserByUsername("aliceW");
        User u = User.get("aliceW");
        associateUserWithOpenId(u);

        // Re-login
        login(jr.createWebClient());
    }

    /**
     * Associates the OpenID identity of the user with {@link #realm}.
     */
    private void associateUserWithOpenId(User u) throws Exception {
        WebClient wc = jr.createWebClient().login(u.getId(), u.getId()/*assumes password==name*/);

        // Associate an OpenID with an existing user
        HtmlPage associated = wc.goTo("federatedLoginService/openid/startAssociate?openid=" + openid.url);
        //assertTrue(associated.getDocumentURI().endsWith("federatedLoginService/openid/onAssociationSuccess")); //TODO: not yet implemented
        OpenIdUserProperty p = u.getProperty(OpenIdUserProperty.class);
        assertEquals(1, p.getIdentifiers().size());
        assertEquals(openid.getUserIdentity(), p.getIdentifiers().iterator().next());
    }

    @Test
    //@Ignore("Failing in old test version and failing manually")
    public void testLogInWithOpenIDAndSignUp() throws Exception {
        openid = createServer();

        realm = jr.createDummySecurityRealm();
        jr.jenkins.setSecurityRealm(realm);

        WebClient wc = jr.createWebClient();
        // Workaround failing ajax requests to build queue
        wc.getOptions().setThrowExceptionOnScriptError(false);

        // Login with OpenID as an unregistered user
        HtmlPage login = wc.goTo("federatedLoginService/openid/login?from=/");
        login.getDocumentElement().getOneHtmlElementByAttribute("a", "title", "log in with OpenID").click();
        HtmlForm loginForm = getFormById(login, "openid_form");
        loginForm.getInputByName("openid").setValueAttribute(openid.url);
        HtmlPage signUp = ((HtmlElement)loginForm.getFirstByXPath("//input[@type='submit']")).click();

        // Sign up user
        HtmlForm signUpForm = getFormByAction(signUp, "/securityRealm/createAccountWithFederatedIdentity");
        signUpForm.getInputByName("password1").setValueAttribute("x");
        signUpForm.getInputByName("password2").setValueAttribute("x");
        HtmlPage loggedIn = jr.submit(signUpForm);

        assertNotNull(loggedIn.getAnchorByHref("/logout"));
        assertNotNull(loggedIn.getAnchorByHref("/user/aliceW"));

        wc.goTo("logout");

        // Re-login
        login(wc);
    }

    /**
     * Creates a OpenID server.
     */
    private OpenIdTestService createServer() throws IOException {
        return new OpenIdTestService(
                getServiceUrl(),
                getProps(),
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(SREG_EXTENSION, AX_EXTENSION, TEAM_EXTENSION));
    }

    private void login(WebClient wc) throws Exception {
        HtmlPage login = wc.goTo("federatedLoginService/openid/login?from=/");
        login.getDocumentElement().getOneHtmlElementByAttribute("a", "title", "log in with OpenID").click();
        HtmlForm loginForm = getFormById(login, "openid_form");
        loginForm.getInputByName("openid").setValueAttribute(openid.url); 
        //HtmlPage loggedIn = ((HtmlElement)loginForm.getFirstByXPath("//input[@type='submit']")).click();
        HtmlPage loggedIn = jr.submit(loginForm);

        assertNotNull(loggedIn.getAnchorByHref("/logout"));
        assertNotNull(loggedIn.getAnchorByHref("/user/aliceW"));
    }

    private HtmlForm getFormById(HtmlPage p, final String id) throws ElementNotFoundException {
        return getFormByAttribute(p, "id", id);
    }

    private HtmlForm getFormByAction(HtmlPage p, final String action) throws ElementNotFoundException {
        return getFormByAttribute(p, "action", action);
    }

    private HtmlForm getFormByAttribute(HtmlPage p, String name, String value) throws ElementNotFoundException {
        final List<HtmlForm> forms = p.getDocumentElement().getElementsByAttribute("form", name, value);
        if (forms.size() == 0) {
            throw new ElementNotFoundException("form", name, value);
        }
        return forms.get(0);
    }

    public static class LoginServiceTestRule extends OpenIdTestCase.OpenIdRule {
        public void before() throws Throwable {
            super.before();
            realm = createDummySecurityRealm();
            jenkins.getDescriptorByType(OpenIdLoginService.GlobalConfigurationImpl.class).setEnabled(true);
        } 
    }
}