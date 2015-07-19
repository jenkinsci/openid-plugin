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
package hudson.plugins.openid.impl;

import com.cloudbees.openid4java.team.TeamExtensionFactory;
import com.cloudbees.openid4java.team.TeamExtensionRequest;
import com.cloudbees.openid4java.team.TeamExtensionResponse;
import com.google.common.collect.Lists;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Use the OpenID team extension (https://dev.launchpad.net/OpenIDTeams) to obtain membership.
 *
 * @author Paul Sandoz
 */
@Extension
public class TeamsExtension extends OpenIdExtension {
    @Override
    public void extend(AuthRequest authRequest) throws MessageException {
        if (DISABLE)    return;

        TeamExtensionRequest req = new TeamExtensionRequest();
        Collection<String> groups = Hudson.getInstance().getAuthorizationStrategy().getGroups();
        req.setQueryMembership(groups);
        authRequest.addExtension(req);

        if (LOGGER.isLoggable(Level.FINE)) {
            LOGGER.fine("Checking memberships of "+new ArrayList<String>(groups)+" with OpenID");
        }
    }

    @Override
    public void process(AuthSuccess authSuccess, Identity id) throws MessageException {
        if (DISABLE)    return;

        TeamExtensionResponse ter = getMessageAs(TeamExtensionResponse.class,  authSuccess, TeamExtensionFactory.URI);
        List<GrantedAuthority> r = id.getGrantedAuthorities();
        for (String s : ter.getTeamMembership())
            r.add(new GrantedAuthorityImpl(s));
        r.add(SecurityRealm.AUTHENTICATED_AUTHORITY);

        if (LOGGER.isLoggable(Level.FINE)) {
            LOGGER.fine("Adding "+ter.getTeamMembership()+" as authorities from team extension to "+id.getOpenId());
        }
    }

    static {
        TeamExtensionFactory.install();
    }

    private static final Logger LOGGER = Logger.getLogger(TeamsExtension.class.getName());

    /**
     * Escape hatch for people affected by JENKINS-14843 until we switch to POST.
     */
    @SuppressFBWarnings(value = "MS_SHOULD_BE_FINAL", 
            justification = "Common Jenkins pstter for configs, which may be changed in the runtime")
    public static boolean DISABLE = Boolean.parseBoolean(
            System.getProperty(TeamsExtension.class.getName()+".disable",
                    System.getProperty(TeamsExtension.class.getName()+"disable")
            )
    );
}
