package hudson.plugins;

import com.cloudbees.openid4java.team.TeamExtensionFactory;
import com.cloudbees.openid4java.team.TeamExtensionRequest;
import com.cloudbees.openid4java.team.TeamExtensionResponse;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.Failure;
import hudson.model.Hudson;
import hudson.security.SecurityRealm;
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.anonymous.AnonymousAuthenticationToken;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.Header;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.openid4java.OpenIDException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.consumer.InMemoryConsumerAssociationStore;
import org.openid4java.consumer.InMemoryNonceVerifier;
import org.openid4java.consumer.VerificationResult;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.discovery.Identifier;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.ParameterList;
import org.openid4java.message.ax.FetchRequest;
import org.openid4java.message.sreg.SRegMessage;
import org.openid4java.message.sreg.SRegRequest;
import org.openid4java.message.sreg.SRegResponse;

import javax.servlet.ServletException;
import java.io.IOException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;

/**
 * @author Kohsuke Kawaguchi
 */
public class OpenIdSsoSecurityRealm extends SecurityRealm {
    private final ConsumerManager manager;
//    private final DiscoveryInformation endpoint;

    // for example, https://login.launchpad.net/+openid
    // 
    public final String endpoint;

    private transient volatile DiscoveryInformation discoveredEndpoint;

    @DataBoundConstructor
    public OpenIdSsoSecurityRealm(String endpoint) throws IOException, OpenIDException {
        manager = new ConsumerManager();
        manager.setAssociations(new InMemoryConsumerAssociationStore());
        manager.setNonceVerifier(new InMemoryNonceVerifier(5000));
        this.endpoint = endpoint;
        getDiscoveredEndpoint();
    }

    private DiscoveryInformation getDiscoveredEndpoint() throws IOException, OpenIDException {
        if (discoveredEndpoint==null)
            discoveredEndpoint = new DiscoveryInformation(new URL(endpoint));
        return discoveredEndpoint;
    }

    /**
     * Login begins with our {@link #doCommenceLogin(StaplerRequest, String)} method.
     */
    @Override
    public String getLoginUrl() {
        return "securityRealm/commenceLogin";
    }

    /**
     * Acegi has this notion that authentication is done 
     */
    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents(
            new AuthenticationManager() {
                public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                    if (authentication instanceof AnonymousAuthenticationToken
                    ||  authentication instanceof UsernamePasswordAuthenticationToken)
                        return authentication;
                    throw new BadCredentialsException("Unexpected authentication type: "+authentication);
                }
            }
            // AFAIK, OpenID doesn't define a way for us to query about other users, so no UserDetailsService
        );
    }

    /**
     * The login process starts from here.
     */
    public HttpResponse doCommenceLogin(StaplerRequest request, @Header("Referer") String referer) throws IOException, OpenIDException {
        final AuthRequest authReq = manager.authenticate(getDiscoveredEndpoint(), Hudson.getInstance().getRootUrl()+"securityRealm/finishLogin?referer="+referer);

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

        // TODO: use a factory method on HttpResponses
        return redirect(url);
    }

    private HttpResponse redirect(final String url) {
        return new HttpResponse() {
            public void generateResponse(StaplerRequest req, StaplerResponse rsp, Object node) throws IOException, ServletException {
                rsp.sendRedirect(url);
            }
        };
    }

    /**
     * 
     */
    public HttpResponse doFinishLogin(StaplerRequest request, @QueryParameter String referer) throws IOException, OpenIDException {
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
                receivingURL.toString(), responselist, getDiscoveredEndpoint());

        // examine the verification result and extract the verified identifier
        Identifier verified = verification.getVerifiedId();
        if (verified == null)
            throw new Failure("Failed to login");

        AuthSuccess authSuccess =
                (AuthSuccess) verification.getAuthResponse();

        String openid = verified.getIdentifier();

        SRegResponse sregResp = (SRegResponse) authSuccess.getExtension(SRegMessage.OPENID_NS_SREG);
        String nick = sregResp.getAttributeValue("nickname");


        TeamExtensionResponse ter = (TeamExtensionResponse) authSuccess.getExtension(TeamExtensionFactory.URI);

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                nick!=null?nick:openid, "", createTeamMemberships(ter));
        SecurityContextHolder.getContext().setAuthentication(token);


        if (referer!=null)  return redirect(referer);
        return HttpResponses.redirectToContextRoot();
    }

    private GrantedAuthority[] createTeamMemberships(TeamExtensionResponse ter) {
        List<String> l = ter.getTeamMembership();
        GrantedAuthority[] r = new GrantedAuthority[l.size()];
        int idx=0;
        for (String s : l)
            r[idx++] = new GrantedAuthorityImpl(s);
        return r;
    }


    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {
        public String getDisplayName() {
            return "OpenID SSO";
        }

        static {
            TeamExtensionFactory.install();
        }
    }
}
