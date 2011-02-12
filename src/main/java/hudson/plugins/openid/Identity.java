package hudson.plugins.openid;

import com.cloudbees.openid4java.team.TeamExtensionFactory;
import com.cloudbees.openid4java.team.TeamExtensionResponse;
import hudson.model.User;
import hudson.security.SecurityRealm;
import hudson.tasks.Mailer;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.openid4java.OpenIDException;
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.ax.AxMessage;
import org.openid4java.message.ax.FetchRequest;
import org.openid4java.message.ax.FetchResponse;
import org.openid4java.message.sreg.SRegMessage;
import org.openid4java.message.sreg.SRegResponse;

import java.io.IOException;
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
        String fullName = sr.getAttributeValue("fullname");
        String email = sr.getAttributeValue("email");

        FetchResponse fr = (FetchResponse)authSuccess.getExtension(AxMessage.OPENID_NS_AX);
        if (fr!=null) {
            if (fullName==null) {
                String first = fr.getAttributeValue("firstName");
                String last = fr.getAttributeValue("lastName");
                if (first!=null & last!=null)
                    fullName = first+" "+last;
            }
            if (email==null)
                email = fr.getAttributeValue("email");
        }
        this.fullName = fullName;
        this.email = email;

//        FetchResponse fr = (FetchResponse) authSuccess.getExtension(AxMessage.OPENID_NS_AX);

        TeamExtensionResponse ter = (TeamExtensionResponse) authSuccess.getExtension(TeamExtensionFactory.URI);
        this.teams = createTeamMemberships(ter);
    }

    /**
     * Obtains the token suitable as the user ID.
     */
    public String getEffectiveNick() {
        if (nick!=null)     return nick;
        if (email!=null)    return email;
        return openId;
    }

    private List<GrantedAuthority> createTeamMemberships(TeamExtensionResponse ter) {
        Set<String> l = ter.getTeamMembership();
        List<GrantedAuthority> r = new ArrayList<GrantedAuthority>();
        for (String s : l)
            r.add(new GrantedAuthorityImpl(s));
        r.add(SecurityRealm.AUTHENTICATED_AUTHORITY);
        return r;
    }

    /**
     * Updates the user information on Hudson based on the information in this identity.
     */
    public void updateProfile(User u) throws IOException {
        // update the user profile by the externally given information
        if (fullName!=null)
            u.setFullName(fullName);
        if (email!=null)
            u.addProperty(new Mailer.UserProperty(email));
    }
}
