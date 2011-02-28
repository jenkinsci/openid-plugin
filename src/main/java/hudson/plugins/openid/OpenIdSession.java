package hudson.plugins.openid;

import com.cloudbees.openid4java.team.TeamExtensionFactory;
import com.cloudbees.openid4java.team.TeamExtensionRequest;
import hudson.model.Failure;
import hudson.model.Hudson;
import org.acegisecurity.GrantedAuthorityImpl;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest;
import org.openid4java.OpenIDException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.consumer.VerificationResult;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.discovery.Identifier;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.ParameterList;
import org.openid4java.message.ax.FetchRequest;
import org.openid4java.message.sreg.SRegRequest;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/**
 * Represents state for an OpenID authentication.
 *
 * @author Kohsuke Kawaguchi
 */
public abstract class OpenIdSession {
    private final ConsumerManager manager;
    private final DiscoveryInformation endpoint;
    private final String finishUrl;

    public OpenIdSession(ConsumerManager manager, DiscoveryInformation endpoint, String finishUrl) {
        this.manager = manager;
        this.endpoint = endpoint;
        this.finishUrl = finishUrl;
    }

    public OpenIdSession(ConsumerManager manager, String openid, String finishUrl) throws OpenIDException {
        this.manager = manager;
        this.finishUrl = finishUrl;

        List discoveries = manager.discover(openid);
        endpoint = manager.associate(discoveries);
    }

    /**
     * Starts the login session.
     */
    public HttpResponse doCommenceLogin() throws IOException, OpenIDException {
        final AuthRequest authReq = manager.authenticate(endpoint, Hudson.getInstance().getRootUrl()+ finishUrl);

        OpenIdExtension.extendRequest(authReq);

        String url = authReq.getDestinationUrl(true);

        // remember this in the session
        Stapler.getCurrentRequest().getSession().setAttribute(SESSION_NAME,this);

        return new HttpRedirect(url);
    }

    /**
     * When the identity provider is done with its thing, the user comes back here.
     */
    public HttpResponse doFinishLogin(StaplerRequest request) throws IOException, OpenIDException {
        // extract the parameters from the authentication process
        // (which comes in as a HTTP extend from the OpenID provider)
        ParameterList responselist = new ParameterList(request.getParameterMap());

        // extract the receiving URL from the HTTP extend
        // Do not use extend.getRequestURL(), since reverse proxies might not be correctly set up
        String receivingURL = Hudson.getInstance().getRootUrl()+finishUrl;
        String queryString = request.getQueryString();
        if (queryString != null && queryString.length() > 0)
            receivingURL+='?'+request.getQueryString();

        // verify the process
        VerificationResult verification = manager.verify(receivingURL, responselist, endpoint);

        // examine the verification result and extract the verified identifier
        Identifier verified = verification.getVerifiedId();
        if (verified == null)
            throw new Failure("Failed to login: " + verification.getStatusMsg());

        AuthSuccess authSuccess = (AuthSuccess) verification.getAuthResponse();
        return onSuccess(new Identity(authSuccess));
    }

    protected abstract HttpResponse onSuccess(Identity identity) throws IOException;

    /**
     * Gets the {@link OpenIdSession} associated with HTTP session in the current extend.
     */
    public static OpenIdSession getCurrent() {
        return (OpenIdSession) Stapler.getCurrentRequest().getSession().getAttribute(SESSION_NAME);
    }

    static {
        TeamExtensionFactory.install();
    }

    private static final String SESSION_NAME = OpenIdSession.class.getName();
}
