package hudson.plugins.openid;

import com.google.common.base.Supplier;
import com.google.common.collect.ListMultimap;
import com.google.common.collect.Lists;
import com.google.common.collect.Multimaps;
import hudson.model.User;
import hudson.tasks.Mailer;
import org.acegisecurity.GrantedAuthority;
import org.openid4java.OpenIDException;
import org.openid4java.message.AuthSuccess;

import java.io.IOException;
import java.util.*;

/**
 * Represents an identity information given by the OpenID provider.
 *
 * @author Kohsuke Kawaguchi
 */
public class Identity {

    private final String openId;
    private String nick;
    private String fullName;
    private String email;
    private final List<GrantedAuthority> teams;
    private final ListMultimap<String, String> properties;

    public Identity(AuthSuccess authSuccess) throws OpenIDException  {
        openId = authSuccess.getIdentity();
        teams = Lists.newArrayList();
        properties = Multimaps.newListMultimap(new TreeMap<String, Collection<String>>(),new Supplier<List<String>>() {
            public List<String> get() {
                return new ArrayList<String>();
            }
        });

        OpenIdExtension.processResponse(authSuccess, this);
    }


    public String getOpenId() {
        return openId;
    }

    public String getNick() {
        return nick;
    }

    public void setNick(String nick) {
        this.nick = nick;
    }

    /**
     * Obtains the token suitable as the user ID.
     */
    public String getEffectiveNick() {
        if (getNick()!=null)     return getNick();
        if (getEmail()!=null)    return getEmail();
        return getOpenId();
    }

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public List<GrantedAuthority> getGrantedAuthorities() {
        return teams;
    }

    public ListMultimap<String, String> getProperties() {
        return properties;
    }

    /**
     * Updates the user information on Hudson based on the information in this identity.
     */
    public void updateProfile(User u) throws IOException {
        // update the user profile by the externally given information
        if (getFullName()!=null)
            u.setFullName(getFullName());
        if (getEmail()!=null)
            u.addProperty(new Mailer.UserProperty(getEmail()));
    }
}
