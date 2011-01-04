package hudson.plugins.openid;

import hudson.model.Hudson;
import hudson.model.User;
import hudson.model.UserProperty;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;
import org.kohsuke.stapler.ForwardToView;
import org.kohsuke.stapler.HttpResponse;

import javax.servlet.ServletException;
import java.io.IOException;

/**
 * @author Kohsuke Kawaguchi
 */
public abstract class FederatedLoginService extends hudson.security.FederatedLoginService {
    public abstract Class<? extends FederatedLoginServiceUserProperty> getUserPropertyClass();

    public User findUserByIdentifier(String id) {
        Class<? extends FederatedLoginServiceUserProperty> pt = getUserPropertyClass();
        for (User u : User.getAll()) {
            if (u.getProperty(pt).has(id))
                return u;
        }
        return null;
    }

    protected boolean onIdentified(String id) {
        User u = findUserByIdentifier(id);
        if (u!=null) {
            // login as this user
            UserDetails d = Hudson.getInstance().getSecurityRealm().loadUserByUsername(u.getId());

            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(d,"",d.getAuthorities());
            token.setDetails(d);
            SecurityContextHolder.getContext().setAuthentication(token);
            return true;
        } else {
            // unassociated identity
            return false;
        }
    }

    protected HttpResponse onAssociated(String id) throws IOException {
        User u = User.current();
        FederatedLoginServiceUserProperty p = u.getProperty(getUserPropertyClass());
        if (p==null) {
            p = (FederatedLoginServiceUserProperty)UserProperty.all().find(getUserPropertyClass()).newInstance(u);
            u.addProperty(p);
        }
        p.addIdentifier(id);

        return new ForwardToView(this,"onAssociationSuccess");
    }
}
