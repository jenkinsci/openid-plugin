package hudson.plugins.openid;

import hudson.Extension;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.openid4java.OpenIDException;
import org.openid4java.consumer.ConsumerException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.consumer.InMemoryConsumerAssociationStore;
import org.openid4java.consumer.InMemoryNonceVerifier;

import java.io.IOException;

/**
 * @author Kohsuke Kawaguchi
 */
@Extension
public class OpenIdLoginService extends FederatedLoginService {
    private final ConsumerManager manager;

    public OpenIdLoginService() throws ConsumerException {
        manager = new ConsumerManager();
        manager.setAssociations(new InMemoryConsumerAssociationStore());
        manager.setNonceVerifier(new InMemoryNonceVerifier(5000));
    }

    @Override
    public String getUrlName() {
        return "openid";
    }

    public Class<? extends FederatedLoginServiceUserProperty> getUserPropertyClass() {
        return OpenIdUserProperty.class;
    }

    /**
     * Commence a login.
     */
    public HttpResponse doLogin(@QueryParameter String openid, @QueryParameter final String from) throws OpenIDException, IOException {
        OpenIdSession s = new OpenIdSession(manager,openid,"federatedLoginService/openid/finish") {
            @Override
            protected HttpResponse onSuccess(Identity identity) throws IOException {
                if (onIdentified(identity.openId)) {
                    if (from!=null)  return new HttpRedirect(from);
                    return HttpResponses.redirectToContextRoot();
                } else
                    // TODO: initiate the sign up
                    throw new UnsupportedOperationException();
            }
        };
        Stapler.getCurrentRequest().getSession().setAttribute(SESSION_NAME,s);
        return s.doCommenceLogin();
    }

    public HttpResponse doFinish(StaplerRequest request) throws IOException, OpenIDException {
        OpenIdSession session = (OpenIdSession) Stapler.getCurrentRequest().getSession().getAttribute(SESSION_NAME);
        if (session==null)  return HttpResponses.error(StaplerResponse.SC_BAD_REQUEST,new Exception("no session"));
        return session.doFinishLogin(request);
    }

    public HttpResponse doAssociate(@QueryParameter String openid) throws OpenIDException, IOException {
        OpenIdSession s = new OpenIdSession(manager,openid,"federatedLoginService/openid/finish") {
            @Override
            protected HttpResponse onSuccess(Identity identity) throws IOException {
                return onAssociated(identity.openId);
            }
        };
        Stapler.getCurrentRequest().getSession().setAttribute(SESSION_NAME,s);
        return s.doCommenceLogin();
    }


    private static final String SESSION_NAME = OpenIdLoginService.class.getName();
}
