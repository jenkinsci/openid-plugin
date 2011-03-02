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