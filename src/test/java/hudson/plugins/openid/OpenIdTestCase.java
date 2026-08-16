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

import static hudson.plugins.openid.OpenIdTestService.IdProperty;

import com.google.common.collect.Maps;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jvnet.hudson.test.JenkinsRule;

/**
 * @author Paul Sandoz
 */
public class OpenIdTestCase {

    Map<IdProperty, String> getPropsAllDifferentEmails() {
        Map<IdProperty, String> props = getProps();
        props.remove(IdProperty.email);
        props.put(IdProperty.email, "alice.wonder@Net");
        props.put(IdProperty.email2, "alice@Net");
        props.put(IdProperty.email3, "alice.wonderland@Net");
        return props;
    }

    Map<IdProperty, String> getPropsAllSameEmails() {
        Map<IdProperty, String> props = getProps();
        props.put(IdProperty.email2, "alice@Net");
        props.put(IdProperty.email3, "alice@Net");
        return props;
    }

    Map<IdProperty, String> getPropsWithAnyTwoDifferentEmails() {
        Map<IdProperty, String> props = getProps();
        props.remove(IdProperty.email);
        props.put(IdProperty.email2, "alice.Wonderland@Net");
        props.put(IdProperty.email3, "alice@Net");
        return props;
    }

    Map<IdProperty, String> getPropsWithAnyTwoSameEmails() {
        Map<IdProperty, String> props = getProps();
        props.remove(IdProperty.email);
        props.put(IdProperty.email, "alice.wonder@Net");
        props.put(IdProperty.email3, "alice@Net");
        return props;
    }

    Map<IdProperty, String> getPropsWithOneEmail() {
        Map<IdProperty, String> props = getProps();
        props.remove(IdProperty.email);
        props.put(IdProperty.email2, "alice.Wonderland@Net");
        return props;
    }

    Map<IdProperty, String> getProps() {
        Map<IdProperty, String> props = Maps.newEnumMap(IdProperty.class);
        props.put(IdProperty.email, "alice@Net");
        props.put(IdProperty.nick, "aliceW");
        props.put(IdProperty.fullName, "Alice Wonderland");
        props.put(IdProperty.firstName, "alice");
        props.put(IdProperty.lastName, "wonderland");
        props.put(IdProperty.derivedFullName, "alice wonderland");
        return props;
    }

    /**
     * Creates the mock OpenID server, registers it as an unprotected root
     * action, and disables CSRF crumbs for the test.
     */
    static OpenIdTestService createOpenIdServer(
            JenkinsRule j,
            Map<IdProperty, String> props,
            Set<String> teams,
            List<OpenIdTestService.ProcessExtension> extensions)
            throws IOException {
        j.jenkins.setCrumbIssuer(null);
        String url = j.getURL().toExternalForm() + "openid/";
        OpenIdTestService openid = new OpenIdTestService(url, props, teams, extensions);
        j.jenkins.getActions().add(openid);
        return openid;
    }
}
