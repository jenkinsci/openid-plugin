package hudson.plugins.openid;

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
}
