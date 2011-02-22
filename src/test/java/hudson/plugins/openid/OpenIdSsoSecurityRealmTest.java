package hudson.plugins.openid;

import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import hudson.model.User;
import org.jvnet.hudson.test.HudsonTestCase;

import java.io.IOException;
import java.util.Map;

import static hudson.plugins.openid.OpenIdTestService.*;

/**
 * @author Paul Sandoz
 */
public class OpenIdSsoSecurityRealmTest extends HudsonTestCase {
    public OpenIdTestService openid;

    @Override
    public void setUp() throws Exception {
        super.setUp();

        // Set to null to avoid errors on association POST requests
        // set from openid4java
        hudson.setCrumbIssuer(null);
    }

    String getServiceUrl() throws IOException {
        return getURL().toExternalForm() + getUrlName() + "/openid/";
    }

    Map<OpenIdTestService.IdProperty,String> getProps() {
        Map<OpenIdTestService.IdProperty,String> props = Maps.newEnumMap(IdProperty.class);
        props.put(IdProperty.email, "alice@Net");
        props.put(IdProperty.nick, "aliceW");
        props.put(IdProperty.fullName, "Alice Wonderland");
        props.put(IdProperty.firstName, "alice");
        props.put(IdProperty.lastName, "wonderland");
        props.put(IdProperty.derivedFullName, "alice wonderland");
        return props;
    }

    void _testLogin(String userName) throws Exception {
        WebClient wc = new WebClient();

        OpenIdSsoSecurityRealm realm = new OpenIdSsoSecurityRealm(openid.url);
        hudson.setSecurityRealm(realm);

        HtmlPage top = wc.goTo("");
        top = top.getAnchorByText("log in").click();

        assertNotNull(top.getAnchorByHref("/logout"));

        assertNotNull(top.getAnchorByHref("/user/" + userName));

        // TODO the following does not get the expected authemtication token implementation
        // it should be an instance of UsernamePasswordAuthenticationToken
        // and from that can verify the granted authorities given by the team extension roles
//        Authentication a = executeOnServer(new Callable<Authentication>() {
//            public Authentication call() throws Exception {
//                return SecurityContextHolder.getContext().getAuthentication();
//            }
//        });
//        assertTrue(a instanceof UsernamePasswordAuthenticationToken);

        User u = User.get(userName);
        assertNotNull(u);
        OpenIdUserProperty p = u.getProperty(OpenIdUserProperty.class);
        assertNotNull(p);

        assertEquals(1, p.getIdentifiers().size());
        assertEquals(openid.getUserIdentity(), p.getIdentifiers().iterator().next());
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

    // TODO uncomment if fall back to fullname is supported
//    public void testLoginWithWithoutAXExtensionAndNickAndEmail() throws Exception {
//        Map<OpenIdTestService.IdProperty,String> props = getProps();
//        props.remove(OpenIdTestService.IdProperty.nick);
//        props.remove(OpenIdTestService.IdProperty.email);
//        openid = new OpenIdTestService(
//                getServiceUrl(),
//                props,
//                Sets.newHashSet("foo", "bar"),
//                Lists.newArrayList(OpenIdTestService.SREG_EXTENSION, OpenIdTestService.TEAM_EXTENSION));
//
//        _testLogin(openid.props.get(IdProperty.firstName));
//    }

    public void testLoginWithWithoutSRegExtension() throws Exception {
        openid = new OpenIdTestService(
                getServiceUrl(),
                getProps(),
                Sets.newHashSet("foo", "bar"),
                Lists.newArrayList(AX_EXTENSION, TEAM_EXTENSION));

        _testLogin(openid.props.get(IdProperty.email));
    }

    // TODO uncomment if fall back to fullname is supported
//    public void testLoginWithWithoutSRegExtensionAndEmailAddress() throws Exception {
//        Map<OpenIdTestService.IdProperty,String> props = getProps();
//        props.remove(OpenIdTestService.IdProperty.email);
//        openid = new OpenIdTestService(
//                getServiceUrl(),
//                props,
//                Sets.newHashSet("foo", "bar"),
//                Lists.newArrayList(OpenIdTestService.AX_EXTENSION, OpenIdTestService.TEAM_EXTENSION));
//
//        _testLogin(openid.props.get(IdProperty.derivedFullName));
//    }
}