package hudson.plugins.openid.impl;

import com.cloudbees.openid4java.team.TeamExtensionFactory;
import com.cloudbees.openid4java.team.TeamExtensionRequest;
import com.cloudbees.openid4java.team.TeamExtensionResponse;
import com.google.common.collect.Lists;
import hudson.Extension;
import hudson.model.Hudson;
import hudson.plugins.openid.Identity;
import hudson.plugins.openid.OpenIdExtension;
import hudson.security.SecurityRealm;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.MessageException;
import org.openid4java.message.ax.AxMessage;
import org.openid4java.message.ax.FetchResponse;
import org.openid4java.message.sreg.SRegMessage;
import org.openid4java.message.sreg.SRegResponse;

import java.util.List;

/**
 * @author Paul Sandoz
 */
@Extension
public class TeamsExtension extends OpenIdExtension {
    @Override
    public void extend(AuthRequest authRequest) throws MessageException {
        TeamExtensionRequest req = new TeamExtensionRequest();
        req.setQueryMembership(Hudson.getInstance().getAuthorizationStrategy().getGroups());
        authRequest.addExtension(req);
    }

    @Override
    public void process(AuthSuccess authSuccess, Identity id) throws MessageException {
        TeamExtensionResponse ter = getMessageAs(TeamExtensionResponse.class,  authSuccess, TeamExtensionFactory.URI);
        List<GrantedAuthority> r = id.getGrantedAuthorities();
        for (String s : ter.getTeamMembership())
            r.add(new GrantedAuthorityImpl(s));
        r.add(SecurityRealm.AUTHENTICATED_AUTHORITY);
    }

    static {
        TeamExtensionFactory.install();
    }
}
