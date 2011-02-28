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
public abstract class OpenIdTestCase extends HudsonTestCase {
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

    Map<IdProperty,String> getProps() {
        Map<IdProperty,String> props = Maps.newEnumMap(IdProperty.class);
        props.put(IdProperty.email, "alice@Net");
        props.put(IdProperty.nick, "aliceW");
        props.put(IdProperty.fullName, "Alice Wonderland");
        props.put(IdProperty.firstName, "alice");
        props.put(IdProperty.lastName, "wonderland");
        props.put(IdProperty.derivedFullName, "alice wonderland");
        return props;
    }
}