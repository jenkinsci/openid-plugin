package hudson.plugins.openid;

import hudson.Extension;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import hudson.security.FederatedLoginServiceUserProperty;
import hudson.util.Secret;
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
        @Override
        public UserProperty newInstance(User user) {
            return new OpenIdUserProperty(Collections.<String>emptySet());
        }

        @Override
        public String getDisplayName() {
            return "OpenID";
        }
    }
}
