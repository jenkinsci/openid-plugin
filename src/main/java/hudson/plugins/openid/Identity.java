package hudson.plugins.openid;

import com.cloudbees.openid4java.team.TeamExtensionFactory;
import com.cloudbees.openid4java.team.TeamExtensionResponse;
import hudson.security.SecurityRealm;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.openid4java.OpenIDException;
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.sreg.SRegMessage;
import org.openid4java.message.sreg.SRegResponse;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Represents an identity information given by the OpenID provider.
 *
 * @author Kohsuke Kawaguchi
 */
public class Identity {
    public final String openId;

    public final String nick;
    public final String fullName;
    public final String email;

    public final List<GrantedAuthority> teams;

    public Identity(AuthSuccess authSuccess) throws OpenIDException  {
        openId = authSuccess.getIdentity();

        SRegResponse sr = (SRegResponse) authSuccess.getExtension(SRegMessage.OPENID_NS_SREG);
        nick = sr.getAttributeValue("nickname");
        fullName = sr.getAttributeValue("fullname");
        email = sr.getAttributeValue("email");

//        FetchResponse fr = (FetchResponse) authSuccess.getExtension(AxMessage.OPENID_NS_AX);

        TeamExtensionResponse ter = (TeamExtensionResponse) authSuccess.getExtension(TeamExtensionFactory.URI);
        this.teams = createTeamMemberships(ter);
    }

    private List<GrantedAuthority> createTeamMemberships(TeamExtensionResponse ter) {
        Set<String> l = ter.getTeamMembership();
        List<GrantedAuthority> r = new ArrayList<GrantedAuthority>();
        for (String s : l)
            r.add(new GrantedAuthorityImpl(s));
        r.add(SecurityRealm.AUTHENTICATED_AUTHORITY);
        return r;
    }
}
