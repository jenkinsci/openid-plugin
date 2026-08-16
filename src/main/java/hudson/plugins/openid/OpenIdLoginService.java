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

import com.google.inject.Inject;
import hudson.Extension;
import hudson.Util;
import hudson.Plugin;
import hudson.model.Failure;
import hudson.model.User;
import hudson.security.FederatedLoginService;
import hudson.security.FederatedLoginServiceUserProperty;
import hudson.security.SecurityRealm;
import java.io.IOException;
import java.net.URI;
import jenkins.model.GlobalConfiguration;
import jenkins.model.GlobalConfigurationCategory;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest2;
import org.kohsuke.stapler.interceptor.RequirePOST;
import org.openid4java.OpenIDException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.consumer.InMemoryConsumerAssociationStore;
import org.openid4java.consumer.InMemoryNonceVerifier;
import org.openid4java.discovery.Discovery;
import org.openid4java.server.RealmVerifierFactory;
import org.openid4java.util.HttpFetcherFactory;
import org.springframework.lang.NonNull;

/**
 * Augments other {@link SecurityRealm} by allowing login via OpenID.
 *
 * @author Kohsuke Kawaguchi
 */
@Extension
public class OpenIdLoginService extends FederatedLoginService {
    @Inject
    private transient Jenkins jenkins;

    private final ConsumerManager manager;

    private static boolean disabled = Boolean.getBoolean(OpenIdLoginService.class.getName() + ".disabled");

    private boolean isSafeRedirectTarget(String url) {
        if (url == null) {
            return false;
        }

        String target = url.trim();
        if (target.isEmpty()) {
            return false;
        }

        // Backslashes are never part of a legitimate same-origin redirect and
        // can be used to smuggle a protocol-relative URL past prefix checks
        // (e.g. "/\evil.com" becomes "//evil.com" in some browsers).
        if (target.indexOf('\\') >= 0 || target.startsWith("//")) {
            return false;
        }

        URI uri;
        try {
            uri = URI.create(target);
        } catch (IllegalArgumentException e) {
            return false;
        }

        // No scheme and no authority: a same-origin path such as "/job/foo".
        if (uri.getScheme() == null && uri.getAuthority() == null) {
            return target.startsWith("/");
        }

        // An absolute URL (https://…) or any URL carrying an authority. Only
        // allow it when it points back at this Jenkins instance.
        String rootUrl = Jenkins.get().getRootUrl();
        if (rootUrl == null) {
            return false;
        }
        try {
            return sameOrigin(uri, URI.create(rootUrl));
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static boolean sameOrigin(URI candidate, URI root) {
        String scheme = candidate.getScheme();
        String host = candidate.getHost();
        return scheme != null
                && host != null
                && scheme.equalsIgnoreCase(root.getScheme())
                && host.equalsIgnoreCase(root.getHost())
                && effectivePort(candidate) == effectivePort(root);
    }

    private static int effectivePort(URI uri) {
        int port = uri.getPort();
        if (port != -1) {
            return port;
        }
        if ("https".equalsIgnoreCase(uri.getScheme())) {
            return 443;
        }
        if ("http".equalsIgnoreCase(uri.getScheme())) {
            return 80;
        }
        return -1;
    }

    public OpenIdLoginService() {
        HttpFetcherFactory fetcherFactory = new HttpFetcherFactory();
        YadisResolver2 resolver = new YadisResolver2(fetcherFactory);
        manager = new ConsumerManager(new RealmVerifierFactory(resolver), new Discovery(), fetcherFactory);
        manager.setAssociations(new InMemoryConsumerAssociationStore());
        manager.setNonceVerifier(new InMemoryNonceVerifier(5000));
        manager.getDiscovery().setYadisResolver(resolver);
    }

    public boolean isDisabled() {
        return disabled
                || !jenkins.getDescriptorByType(GlobalConfigurationImpl.class).isEnabled()
                || jenkins.getSecurityRealm() instanceof OpenIdSsoSecurityRealm;
    }

    // TODO: Such usage of static fields is a bad practice in any case.

    /**
     * Globally sets the disabled flag on {@link OpenIdLoginService} instances.
     * @param isDisabled Flag to be set
     * @deprecated Use {@link #setDisabledGlobal(boolean)}
     */
    @Deprecated
    public void setDisabled(boolean isDisabled) {
        setDisabledGlobal(isDisabled);
    }

    /**
     * Globally sets the disabled flag on {@link OpenIdLoginService} instances.
     * @param isDisabled Flag to be set
     * @since TODO
     */
    public static void setDisabledGlobal(boolean isDisabled) {
        disabled = isDisabled;
    }

    @Override
    @NonNull
    public String getUrlName() {
        return "openid";
    }

    @NonNull
    public Class<? extends FederatedLoginServiceUserProperty> getUserPropertyClass() {
        return OpenIdUserProperty.class;
    }

    /**
     * Commence a login.
     */
    @RequirePOST
    public HttpResponse doStartLogin(
            @QueryParameter String openid, @QueryParameter String openid_identifier, @QueryParameter String from)
            throws OpenIDException, IOException {
        if (isDisabled()) {
            return HttpResponses.notFound();
        }
        // if the script doesn't work, it'll submit 'openid_identifier'
        // <INPUT type=text NAME=openid/> is programmatically constructed
        if (openid == null) {
            openid = openid_identifier;
        }

        OpenIdSession session = new OpenIdSession(manager, openid, getFinishUrl()) {
            @Override
            protected HttpResponse onSuccess(Identity identity) throws IOException {
                IdentityImpl id = new IdentityImpl(identity);
                User u = id.signin();
                id.id.updateProfile(u);
                String requestedUrl = getFrom();

                if (isSafeRedirectTarget(requestedUrl)) {
                    return HttpResponses.redirectTo(requestedUrl);
                }

                return HttpResponses.redirectToContextRoot();
            }
        };
        session.setFrom(from);
        return session.doCommenceLogin();
    }

    private String getFinishUrl() {
        StaplerRequest2 req = Stapler.getCurrentRequest2();
        String contextPath = req.getContextPath();
        if (Util.fixEmptyAndTrim(contextPath) == null || "/".equals(contextPath)) {
            return "federatedLoginService/openid/finish";
        } else {
            // hack alert... work around some less than consistent servlet containers
            String trimmedContextPath = contextPath;
            if (trimmedContextPath.startsWith("/")) {
                trimmedContextPath = trimmedContextPath.substring(1);
            }
            if (trimmedContextPath.endsWith("/")) {
                trimmedContextPath = trimmedContextPath.substring(0, trimmedContextPath.length() - 1);
            }
            return trimmedContextPath + "/federatedLoginService/openid/finish";
        }
    }

    public HttpResponse doFinish(StaplerRequest2 request) throws IOException, OpenIDException {
        if (isDisabled()) {
            return HttpResponses.notFound();
        }
        OpenIdSession session = OpenIdSession.getCurrent();
        if (session == null) {
            throw new Failure(Messages.OpenIdLoginService_SessionNotFound());
        }
        return session.doFinishLogin(request);
    }

    @RequirePOST
    public HttpResponse doStartAssociate(@QueryParameter String openid, @QueryParameter String openid_identifier)
            throws OpenIDException, IOException {
        if (isDisabled()) {
            return HttpResponses.notFound();
        }

        // if the script doesn't work, it'll submit 'openid_identifier'
        // <INPUT type=text NAME=openid/> is programmatically constructed
        if (openid == null) {
            openid = openid_identifier;
        }

        return new OpenIdSession(manager, openid, getFinishUrl()) {
            @Override
            protected HttpResponse onSuccess(Identity identity) throws IOException {
                new IdentityImpl(identity).addToCurrentUser();
                return new HttpRedirect("onAssociationSuccess");
            }
        }.doCommenceLogin();
    }

    public class IdentityImpl extends FederatedLoginService.FederatedIdentity {
        private final Identity id;

        public IdentityImpl(Identity id) {
            this.id = id;
        }

        @Override
        public String getIdentifier() {
            return id.getOpenId();
        }

        @Override
        public String getNickname() {
            return id.getEffectiveNick();
        }

        @Override
        public String getFullName() {
            return id.getFullName();
        }

        @Override
        public String getEmailAddress() {
            return id.getEmail();
        }

        @Override
        public String getPronoun() {
            return "OpenID";
        }
    }

    @Extension
    public static class GlobalConfigurationImpl extends GlobalConfiguration {

        private boolean enabled;

        public GlobalConfigurationImpl() {
            super();
            if (getConfigFile().exists()) {
                load();
            } else {
                // need to detect if this is a legacy upgrade
                Plugin openIdPlugin = Jenkins.get().getPlugin("openid");
                if (openIdPlugin != null) {
                    setEnabled(openIdPlugin.getWrapper().isDowngradable());
                }
            }
        }

        // Used by Jelly
        public boolean isHidden() {
            return disabled;
        }

        public boolean isEnabled() {
            return enabled && !disabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
            save();
        }

        @Override
        public boolean configure(StaplerRequest2 req, JSONObject json) {
            req.bindJSON(this, json);
            return true;
        }

        @Override
        public GlobalConfigurationCategory getCategory() {
            return GlobalConfigurationCategory.get(GlobalConfigurationCategory.Security.class);
        }
    }
}
