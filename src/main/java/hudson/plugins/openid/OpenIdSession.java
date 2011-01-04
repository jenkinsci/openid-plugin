package hudson.plugins.openid;

import com.cloudbees.openid4java.team.TeamExtensionFactory;
import com.cloudbees.openid4java.team.TeamExtensionRequest;
import hudson.model.Failure;
import hudson.model.Hudson;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
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

import javax.servlet.ServletException;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/**
 * @author Kohsuke Kawaguchi
 */
public abstract class OpenIdSession {
    private final ConsumerManager manager;
    private final DiscoveryInformation endpoint;
    private final String thisUrl;

    public OpenIdSession(ConsumerManager manager, DiscoveryInformation endpoint, String thisUrl) {
        this.manager = manager;
        this.endpoint = endpoint;
        this.thisUrl = thisUrl;
    }

    public OpenIdSession(ConsumerManager manager, String openid, String thisUrl) throws OpenIDException {
        this.manager = manager;
        this.thisUrl = thisUrl;

        List discoveries = manager.discover(openid);
        endpoint = manager.associate(discoveries);
    }

    /**
     * Starts the login session.
     */
    public HttpResponse doCommenceLogin() throws IOException, OpenIDException {
        final AuthRequest authReq = manager.authenticate(endpoint, Hudson.getInstance().getRootUrl()+thisUrl+"/finishLogin");

        // request some user information
        // see http://code.google.com/apis/accounts/docs/OpenID.html
        FetchRequest fetch = FetchRequest.createFetchRequest();
        fetch.addAttribute("email", "http://schema.openid.net/contact/email", false);
        fetch.addAttribute("ff", "http://axschema.org/namePerson", false);
        fetch.addAttribute("img", "http://axschema.org/media/image/default/", false);
        authReq.addExtension(fetch);

        SRegRequest sregReq = SRegRequest.createFetchRequest();
        sregReq.addAttribute("fullname", true);
        sregReq.addAttribute("nickname", true);
        sregReq.addAttribute("email", true);
        authReq.addExtension(sregReq);

        // request team information
        TeamExtensionRequest req = new TeamExtensionRequest();
        req.setQueryMembership(Arrays.asList("foo","shopalong-devs"));
        authReq.addExtension(req);

        String url = authReq.getDestinationUrl(true);

        return new HttpRedirect(url);
    }

    public HttpResponse doFinishLogin(StaplerRequest request) throws IOException, OpenIDException {
        // --- processing the authentication response

        // extract the parameters from the authentication response
        // (which comes in as a HTTP request from the OpenID provider)
        ParameterList responselist =
                new ParameterList(request.getParameterMap());

        // extract the receiving URL from the HTTP request
        StringBuffer receivingURL = request.getRequestURL();
        String queryString = request.getQueryString();
        if (queryString != null && queryString.length() > 0)
            receivingURL.append("?").append(request.getQueryString());

        // verify the response
        VerificationResult verification = manager.verify(
                receivingURL.toString(), responselist, endpoint);

        // examine the verification result and extract the verified identifier
        Identifier verified = verification.getVerifiedId();
        if (verified == null)
            throw new Failure("Failed to login");

        AuthSuccess authSuccess =
                (AuthSuccess) verification.getAuthResponse();

        return onSuccess(new Identity(authSuccess));
//        String openid = verified.getIdentifier();
//
//        SRegResponse sr = (SRegResponse) authSuccess.getExtension(SRegMessage.OPENID_NS_SREG);
//        String nick = sr.getAttributeValue("nickname");
//        String fullName = sr.getAttributeValue("fullname");
//        String email = sr.getAttributeValue("email");
//
//        FetchResponse fr = (FetchResponse) authSuccess.getExtension(AxMessage.OPENID_NS_AX);
//
//        TeamExtensionResponse ter = (TeamExtensionResponse) authSuccess.getExtension(TeamExtensionFactory.URI);
//
//        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
//                nick!=null?nick:openid, "", createTeamMemberships(ter));
//        // token.setDetails();  TODO: set user details service
//        SecurityContextHolder.getContext().setAuthentication(token);
//
//        if (referer!=null)  return redirect(referer);
//        return HttpResponses.redirectToContextRoot();
    }

    protected abstract HttpResponse onSuccess(Identity identity) throws IOException;

    static {
        TeamExtensionFactory.install();
    }
}
