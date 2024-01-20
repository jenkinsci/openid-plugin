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
    
    public Identity(AuthSuccess authSuccess) throws OpenIDException {
        openId = authSuccess.getIdentity();
        teams = Lists.newArrayList();
        properties = Multimaps.newListMultimap(new TreeMap<>(), ArrayList::new);
        
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
        if (getNick() != null) {
            return getNick();
        }
        if (getEmail() != null) {
            return getEmail();
        }
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
        if (getFullName() != null) {
            u.setFullName(getFullName());
        }
        if (getEmail() != null) {
            u.addProperty(new Mailer.UserProperty(getEmail()));
        }
    }
}
