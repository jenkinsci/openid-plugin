package hudson.plugins.openid;

import com.gargoylesoftware.htmlunit.ElementNotFoundException;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlInput;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import com.octo.captcha.service.CaptchaServiceException;
import com.octo.captcha.service.image.DefaultManageableImageCaptchaService;
import hudson.model.User;
import hudson.security.HudsonPrivateSecurityRealm;
import hudson.security.SecurityRealm;
import org.jvnet.hudson.test.HudsonTestCase;
import org.jvnet.hudson.test.recipes.WithPlugin;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static hudson.plugins.openid.OpenIdTestService.*;

/**
 * @author Paul Sandoz
 */
public class OpenIdLoginServiceTest extends OpenIdTestCase {

    public void testAssociateThenLogoutThenLogInWithOpenID() throws Exception {
        openid = new OpenIdTestService(
                getServiceUrl(),
                getProps(),
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(SREG_EXTENSION, AX_EXTENSION, TEAM_EXTENSION));

        HudsonPrivateSecurityRealm realm = new HudsonPrivateSecurityRealm(false);
        hudson.setSecurityRealm(realm);
        User u = realm.createAccount("aliceW", "aliceW");

        WebClient wc = new WebClient().login("aliceW", "aliceW");

        // Associate an OpenID with an existing user
        HtmlPage associated = wc.goTo("federatedLoginService/openid/startAssociate?openid=" + openid.url);
        assertTrue(associated.getDocumentURI().endsWith("federatedLoginService/openid/onAssociationSuccess"));
        OpenIdUserProperty p = u.getProperty(OpenIdUserProperty.class);
        assertEquals(1, p.getIdentifiers().size());
        assertEquals(openid.getUserIdentity(), p.getIdentifiers().iterator().next());

        wc.goTo("logout");

        // Re-login
        login(wc);
    }

    public void testLogInWithOpenIDAndSignUp() throws Exception {
        // Override validation of Captcha service
        SecurityRealm.CaptchaService.INSTANCE = new DefaultManageableImageCaptchaService() {
            public Boolean validateResponseForID(String ID, Object response) throws CaptchaServiceException {
                return true;
            }
        };

        openid = new OpenIdTestService(
                getServiceUrl(),
                getProps(),
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(SREG_EXTENSION, AX_EXTENSION, TEAM_EXTENSION));

        hudson.setSecurityRealm(new HudsonPrivateSecurityRealm(true));

        WebClient wc = new WebClient();
        // Workaround failing ajax requests to build queue
        wc.setThrowExceptionOnFailingAjax(false);

        // Login with OpenID as an unregistered user
        HtmlPage login = wc.goTo("federatedLoginService/openid/login?from=/");
        login.getDocumentElement().getOneHtmlElementByAttribute("a", "title", "log in with OpenID").click();
        HtmlForm loginForm = getFormById(login, "openid_form");
        loginForm.getInputByName("openid").setValueAttribute(openid.url);
        HtmlPage signUp = (HtmlPage)loginForm.submit();

        // Sign up user
        HtmlForm signUpForm = getFormByAction(signUp, "/securityRealm/createAccountWithFederatedIdentity");
        signUpForm.getInputByName("password1").setValueAttribute("x");
        signUpForm.getInputByName("password2").setValueAttribute("x");
        HtmlPage loggedIn = submit(signUpForm);

        assertNotNull(loggedIn.getAnchorByHref("/logout"));
        assertNotNull(loggedIn.getAnchorByHref("/user/aliceW"));

        wc.goTo("logout");

        // Re-login
        login(wc);
    }

    private void login(WebClient wc) throws Exception {
        HtmlPage login = wc.goTo("federatedLoginService/openid/login?from=/");
        login.getDocumentElement().getOneHtmlElementByAttribute("a", "title", "log in with OpenID").click();
        HtmlForm loginForm = getFormById(login, "openid_form");
        loginForm.getInputByName("openid").setValueAttribute(openid.url);
        HtmlPage loggedIn = (HtmlPage)loginForm.submit();

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
}