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

import com.cloudbees.openid4java.team.TeamExtensionFactory;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.Failure;
import hudson.model.User;
import hudson.security.SecurityRealm;
import hudson.util.FormValidation;
import jenkins.security.SecurityListener;
import jenkins.model.Jenkins;
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.anonymous.AnonymousAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.interceptor.RequirePOST;
import org.openid4java.OpenIDException;
import org.openid4java.consumer.ConsumerException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.consumer.InMemoryConsumerAssociationStore;
import org.openid4java.consumer.InMemoryNonceVerifier;
import org.openid4java.discovery.Discovery;
import org.openid4java.discovery.DiscoveryException;
import org.openid4java.server.RealmVerifierFactory;
import org.openid4java.util.HttpClientFactory;
import org.openid4java.util.HttpFetcherFactory;
import org.openid4java.util.ProxyProperties;

import java.io.IOException;

/**
 * SSO based on OpenID by fixing a provider.
 *
 * @author Kohsuke Kawaguchi
 */
public class OpenIdSsoSecurityRealm extends SecurityRealm {
    private /*almost final*/ transient volatile ConsumerManager manager;
    
    // for example, https://login.launchpad.net/+openid
    // 
    public final String endpoint;
    
    @DataBoundConstructor
    public OpenIdSsoSecurityRealm(String endpoint) throws IOException, OpenIDException {
        this.endpoint = endpoint;
        addProxyPropertiesToHttpClient();
    }
    
    private ConsumerManager getManager() throws ConsumerException {
        if (manager != null) {
            return manager;
        }
        
        synchronized (this) {
            if (manager == null) {
                final ConsumerManager managerInitializer = createManager();
                managerInitializer.setAssociations(new InMemoryConsumerAssociationStore());
                managerInitializer.setNonceVerifier(new InMemoryNonceVerifier(5000));
                // We assign the value only after the complete object initialization
                manager = managerInitializer;
            }
        }
        return manager;
    }
    
    protected ConsumerManager createManager() throws ConsumerException {
        HttpFetcherFactory fetcherFactory = new HttpFetcherFactory();
        YadisResolver2 resolver = new YadisResolver2(fetcherFactory);
        ConsumerManager manager = new ConsumerManager(new RealmVerifierFactory(resolver), new Discovery(), fetcherFactory);
        manager.setAssociations(new InMemoryConsumerAssociationStore());
        manager.setNonceVerifier(new InMemoryNonceVerifier(5000));
        manager.getDiscovery().setYadisResolver(resolver); return manager;
    }
    
    protected void addProxyPropertiesToHttpClient() {
        Jenkins instance = Jenkins.get();
        if (instance.proxy != null) {
            ProxyProperties props = new ProxyProperties();
            props.setProxyHostName(instance.proxy.name);
            props.setProxyPort(instance.proxy.port);
            // Do not populate userName and password if userName 
            // has not been specified. 
            if (instance.proxy.getUserName() != null) {
                props.setUserName(instance.proxy.getUserName());
                props.setPassword(instance.proxy.getPassword());
            }
            
            HttpClientFactory.setProxyProperties(props);
        }
    }
    
    /**
     * Login begins with our {@link #doCommenceLogin(String)} method.
     */
    @Override
    public String getLoginUrl() {
        return "securityRealm/commenceLogin";
    }
    
    /**
     * Acegi has this notion that first an {@link Authentication} object is created
     * by collecting user information and then the act of authentication is done
     * later (by {@link AuthenticationManager}) to verify it. But in case of OpenID,
     * we create an {@link Authentication} only after we verified the user identity,
     * so {@link AuthenticationManager} becomes no-op.
     * @return Created {@link SecurityComponents}
     */
    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents(
                (org.springframework.security.authentication.AuthenticationManager) authentication -> {
                    if (authentication instanceof AnonymousAuthenticationToken) {
                        return authentication;
                    }
                    throw new BadCredentialsException("Unexpected authentication type: " + authentication);
                }
                // AFAIK, OpenID doesn't define a way for us to query about other users, so no UserDetailsService
        );
    }
    
    /**
     * The login process starts from here.
     */
    public HttpResponse doCommenceLogin(@QueryParameter String from) throws IOException, OpenIDException {
        if (from == null || !from.startsWith("/")) {
            StaplerRequest currentRequest = Stapler.getCurrentRequest();
            if (currentRequest.getHeader("Referer") != null) {
                from = currentRequest.getHeader("Referer");
            } else {
                from = Jenkins.get().getRootUrl();
            }
        }
        
        String referer = from;
        
        return new OpenIdSession(getManager(), endpoint, "securityRealm/finishLogin") {
            @Override
            protected HttpResponse onSuccess(Identity id) throws IOException {
                // Create the user if needed and update the profile.
                User u = User.get(id.getEffectiveNick());
                id.updateProfile(u);
                OpenIdUserProperty p = u.getProperty(OpenIdUserProperty.class);
                if(p != null) {
                    p.addIdentifier(id.getOpenId());
                }
                
                GrantedAuthority[] grantedAuthorities = id.getGrantedAuthorities().toArray(new GrantedAuthority[0]);
                
                // Because of JENKINS-36709 we log this user in after getting it.
                // so that we use the correct id.
                UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                        u.getId(), "", grantedAuthorities);
                SecurityContextHolder.getContext().setAuthentication(token);
                
                UserDetails userDetails = new OpenIdSsoUserDetails(u.getId(), grantedAuthorities);
                SecurityListener.fireAuthenticated(userDetails);
                
                return new HttpRedirect(referer);
            }
        }.doCommenceLogin();
    }
    
    /**
     * This is where the user comes back to at the end of the OpenID redirect ping-pong.
     */
    public HttpResponse doFinishLogin(StaplerRequest request) throws IOException, OpenIDException {
        OpenIdSession session = OpenIdSession.getCurrent();
        if (session == null) {
            throw new Failure(Messages.OpenIdLoginService_SessionNotFound());
        }
        return session.doFinishLogin(request);
    }
    
    /**
     * Allow OpenId SSO Security Realms to determine the extensions that are applicable.
     * @param openIdExtension the extension.
     * @return {@code true} if this extension is appropriate.
     * @since 2.2
     */
    public boolean isApplicable(OpenIdExtension openIdExtension) {
        return true;
    }
    
    @Extension
    public static class DescriptorImpl extends Descriptor<SecurityRealm> {
        public String getDisplayName() {
            return "OpenID SSO";
        }
        
        @RequirePOST
        public FormValidation doValidate(@QueryParameter String endpoint) throws Exception {
            if (!Jenkins.getActiveInstance().hasPermission(Jenkins.ADMINISTER)) {
                // require admin to test
                return FormValidation.ok();
            }
            try {
                new Discovery().discover(endpoint);
                return FormValidation.ok("OK");
            } catch (DiscoveryException e) {
                return FormValidation.error(e, "Invalid provider URL: " + endpoint);
            }
        }
        
        static {
            TeamExtensionFactory.install();
        }
    }
}
