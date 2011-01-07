package hudson.plugins.openid;

import com.gargoylesoftware.htmlunit.html.HtmlPage;
import hudson.model.User;
import hudson.security.HudsonPrivateSecurityRealm;
import org.jvnet.hudson.test.HudsonTestCase;

/**
 * @author Kohsuke Kawaguchi
 */
public class OpenIdUserPropertyTest extends HudsonTestCase {
    public void testRoundtrip() throws Exception {
        HudsonPrivateSecurityRealm realm = new HudsonPrivateSecurityRealm(false);
        hudson.setSecurityRealm(realm);
        User u = realm.createAccount("alice", "alice");

        // submit empty config
        WebClient wc = new WebClient().login("alice", "alice");
        submit(wc.goTo("user/alice/configure").getFormByName("config"));

        OpenIdUserProperty p = u.getProperty(OpenIdUserProperty.class);
        assertTrue(p.getIdentifiers().isEmpty());


        // submit a non-empty config
        p.addIdentifier("http://me.cloudbees.com/");
        submit(wc.goTo("user/alice/configure").getFormByName("config"));
        p = u.getProperty(OpenIdUserProperty.class);
        assertTrue(p.has("http://me.cloudbees.com/"));
    }

    /**
     * Configuration roundtrip testing when the security realm doesn't support
     * OpenID.
     */
    public void testDisabledRoundtrip() throws Exception {
        User u = User.get("alice");
        u.save();

        // submit empty config
        WebClient wc = createWebClient();
        HtmlPage pg = wc.goTo("user/alice/configure");

        // should see no OpenID in the page
        assertFalse(pg.getWebResponse().getContentAsString().contains("OpenID"));

        submit(pg.getFormByName("config"));

        // should see No OpenID descriptor
        OpenIdUserProperty p = u.getProperty(OpenIdUserProperty.class);
        assertNull(p);
    }
}
