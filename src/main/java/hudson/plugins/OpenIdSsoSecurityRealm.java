package hudson.plugins;

import com.cloudbees.openid4java.team.TeamExtensionFactory;
import com.cloudbees.openid4java.team.TeamExtensionRequest;
import com.cloudbees.openid4java.team.TeamExtensionResponse;
import groovy.lang.Binding;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.Failure;
import hudson.model.Hudson;
import hudson.security.SecurityRealm;
import hudson.util.spring.BeanBuilder;
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.anonymous.AnonymousAuthenticationToken;
import org.acegisecurity.userdetails.User;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.jvnet.libpam.UnixUser;
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
import org.openid4java.message.sreg.SRegRequest;
import org.springframework.dao.DataAccessException;
import org.springframework.web.context.WebApplicationContext;

import javax.servlet.ServletException;
import java.io.IOException;
import java.net.URL;
import java.util.Arrays;

/**
 * @author Kohsuke Kawaguchi
 */
public class OpenIdSsoSecurityRealm extends SecurityRealm {
    private final ConsumerManager manager;
    private final DiscoveryInformation endpoint;

    public OpenIdSsoSecurityRealm() throws IOException, OpenIDException {
        manager = new ConsumerManager();
        manager.setAssociations(new InMemoryConsumerAssociationStore());
        manager.setNonceVerifier(new InMemoryNonceVerifier(5000));
        endpoint = new DiscoveryInformation(new URL("https://login.launchpad.net/+openid"));
    }

    /**
     * Login begins with our {@link #doCommenceLogin()} method.
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
        final AuthRequest authReq = manager.authenticate(endpoint, Hudson.getInstance().getRootUrl()+"securityRealm/finishLogin?referer="+referer);

        // request some user information
        // see http://code.google.com/apis/accounts/docs/OpenID.html
        FetchRequest fetch = FetchRequest.createFetchRequest();
        fetch.addAttribute("email", "http://schema.openid.net/contact/email", true);
        fetch.addAttribute("ff", "http://axschema.org/namePerson/first", true);
        fetch.addAttribute("ll", "http://axschema.org/namePerson/last", true);
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
                receivingURL.toString(), responselist, endpoint);

        // examine the verification result and extract the verified identifier
        Identifier verified = verification.getVerifiedId();
        if (verified == null)
            throw new Failure("Failed to login");

        AuthSuccess authSuccess =
                (AuthSuccess) verification.getAuthResponse();

        String openid = authSuccess.getIdentity();
        String claimedOpenid = authSuccess.getClaimed();

        TeamExtensionResponse ter = (TeamExtensionResponse) authSuccess.getExtension(TeamExtensionFactory.URI);
        System.out.println(ter.getTeamMembership());

        if (referer!=null)  return redirect(referer);
        return HttpResponses.redirectToContextRoot();
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
