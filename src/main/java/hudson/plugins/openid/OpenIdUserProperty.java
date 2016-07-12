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

import com.google.inject.Inject;
import hudson.Extension;
import hudson.model.Hudson;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.FederatedLoginService;
import hudson.security.FederatedLoginServiceUserProperty;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import org.kohsuke.stapler.DataBoundConstructor;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static hudson.Util.*;

/**
 * @author Kohsuke Kawaguchi
 */
public class OpenIdUserProperty extends FederatedLoginServiceUserProperty {
    @DataBoundConstructor
    public OpenIdUserProperty(Set<String> identifiers) {
        super(unencrypt(fixNull(identifiers)));
    }

    /**
     * Reverse the effect of {@link #getProtectedOpenIDs()}.
     */
    private static List<String> unencrypt(Set<String> identifiers) {
        List<String> r = new ArrayList<String>();
        for (String id : identifiers)
            r.add(Secret.fromString(id).getPlainText());
        return r;
    }

    public List<Secret> getProtectedOpenIDs() {
        List<Secret> r = new ArrayList<Secret>();
        for (String id : getIdentifiers())
            r.add(Secret.fromString(id));
        return r;
    }

    @Extension
    public static class DescriptorImpl extends UserPropertyDescriptor {

        @Inject
        private OpenIdLoginService openIdLoginService;

        @Override
        public UserProperty newInstance(User user) {
            return new OpenIdUserProperty(Collections.<String>emptySet());
        }

        @Override
        public boolean isEnabled() {
            Jenkins jenkins = Jenkins.getInstance();
            if(jenkins == null){
                throw new IllegalStateException("No Jenkins instance has been found.");
            }
            return jenkins.getSecurityRealm() instanceof AbstractPasswordBasedSecurityRealm
                    && (openIdLoginService != null && !openIdLoginService.isDisabled());
        }

        @Override
        public String getDisplayName() {
            return "OpenID";
        }
    }
}
