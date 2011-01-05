package hudson.plugins.openid;

import hudson.Extension;
import hudson.model.User;
import hudson.model.UserProperty;
import hudson.model.UserPropertyDescriptor;
import org.kohsuke.stapler.DataBoundConstructor;

import java.util.Collections;
import java.util.Set;

import static hudson.Util.*;

/**
 * @author Kohsuke Kawaguchi
 */
public class OpenIdUserProperty extends FederatedLoginServiceUserProperty {
    @DataBoundConstructor
    public OpenIdUserProperty(Set<String> identifiers) {
        super(fixNull(identifiers));
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
