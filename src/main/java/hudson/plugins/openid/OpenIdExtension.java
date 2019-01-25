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

import hudson.ExtensionList;
import hudson.ExtensionPoint;
import hudson.security.SecurityRealm;
import jenkins.model.Jenkins;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.MessageException;
import org.openid4java.message.MessageExtension;
import org.openid4java.message.ax.FetchRequest;

/**
 * An OpenID extension for extending an authentication request and processing an authentication success.
 *
 * TODO currently there is no mechanism to add general properties to the User or the OpenIdUserProperty
 *
 * @author Paul Sandoz
 */
public abstract class OpenIdExtension implements ExtensionPoint {
    
    /**
     * Allow Extensions to determine that they are applicable when used with specific security realms.
     * @param realm the realm.
     * @return {@code true} if this extension is appropriate.
     * @since 2.2
     */
    public boolean isApplicable(SecurityRealm realm) {
        return !(realm instanceof OpenIdSsoSecurityRealm) || ((OpenIdSsoSecurityRealm) realm).isApplicable(this);
    }
    
    /**
     * Extend the authentication request.
     * <p>
     * The implementation may add extensions to <code>authRequest</code> using
     * {@link AuthRequest#addExtension(org.openid4java.message.MessageExtension)}.
     *
     * @param authRequest the authentication request
     * @throws MessageException if there is a message error extending the request
     */
    public abstract void extend(AuthRequest authRequest) throws MessageException;
    
    /**
     * Process the authentication success.
     * <p>
     * The implementation may extract {@link MessageExtension} implementations from <code>authSuccess</code>
     * and add information to <code>id</code>.
     *
     * @param authSuccess the authentication success.
     * @param id the identity.
     * @throws MessageException if there is a message error processing the success.
     */
    public abstract void process(AuthSuccess authSuccess, Identity id) throws MessageException;
    
    public void extendFetch(FetchRequest request) throws MessageException {}
    
    /**
     * Obtain an extended response message from an {@link AuthSuccess} instance given the class
     * and URI type of the response message.
     *
     * @param c the class of the response message.
     * @param authSuccess the authorization success.
     * @param typeUri the URI type of the response message.
     * @param <T> the type of the response message.
     * @return the response message, otherwise null if there is not such response message available.
     * @throws MessageException if an error obtaining the response message.
     */
    protected <T> T getMessageAs(Class<T> c, AuthSuccess authSuccess, String typeUri) throws MessageException {
        MessageExtension me = authSuccess.getExtension(typeUri);
        return c.cast(me);
    }
    
    /**
     * All registered extension points.
     */
    public static ExtensionList<OpenIdExtension> all() {
        return Jenkins.get().getExtensionList(OpenIdExtension.class);
    }
    
    /**
     * Extend the authentication request.
     * <p>
     * All extension points will be iterated through and each one will extend the request.
     *
     * @param authRequest the authentication request.
     * @throws MessageException if there is a message error extending the request
     * @throws IllegalStateException if there is no Jenkins instance
     */
    public static void extendRequest(AuthRequest authRequest) throws MessageException {
        FetchRequest request = FetchRequest.createFetchRequest();
        SecurityRealm sr = Jenkins.get().getSecurityRealm();
        for (OpenIdExtension e : all()) {
            if (e.isApplicable(sr)) {
                e.extend(authRequest);
                e.extendFetch(request);
            }
        }
        authRequest.addExtension(request);
    }
    
    /**
     * Process the authentication success.
     * <p>
     * All extension points will be iterated through and each one will process the success.
     *
     * @param authSuccess the authentication success.
     * @param id the identity.
     * @throws MessageException if there is a message error processing the success.
     * @throws IllegalStateException if there is no Jenkins instance
     */
    public static void processResponse(AuthSuccess authSuccess, Identity id) throws MessageException {
        SecurityRealm sc = Jenkins.get().getSecurityRealm();
        for (OpenIdExtension e : all()) {
            if (e.isApplicable(sc)) {
                e.process(authSuccess, id);
            }
        }
    }
}