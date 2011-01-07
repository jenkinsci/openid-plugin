package hudson.plugins.openid;

import hudson.Extension;
import hudson.model.User;
import hudson.security.FederatedLoginService;
import hudson.security.FederatedLoginServiceUserProperty;
import hudson.tasks.Mailer;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
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
    public HttpResponse doStartLogin(@QueryParameter String openid, @QueryParameter final String from) throws OpenIDException, IOException {
        return new OpenIdSession(manager,openid,"federatedLoginService/openid/finish") {
            @Override
            protected HttpResponse onSuccess(Identity identity) throws IOException {
                try {
                    User u = new IdentityImpl(identity).signin();

                    // update the user profile by the externally given information
                    if (identity.fullName!=null)
                        u.setFullName(identity.fullName);
                    if (identity.email!=null)
                        u.addProperty(new Mailer.UserProperty(identity.email));

                    return HttpResponses.redirectToContextRoot();
                } catch (UnclaimedIdentityException e) {
                    // TODO: initiate the sign up
                    throw new UnsupportedOperationException();
                }
            }
        }.doCommenceLogin();
    }

    public HttpResponse doFinish(StaplerRequest request) throws IOException, OpenIDException {
        return OpenIdSession.getCurrent().doFinishLogin(request);
    }

    public HttpResponse doStartAssociate(@QueryParameter String openid) throws OpenIDException, IOException {
        return new OpenIdSession(manager,openid,"federatedLoginService/openid/finish") {
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
            return id.openId;
        }

        @Override
        public String getNickname() {
            return id.nick;
        }

        @Override
        public String getFullName() {
            return id.fullName;
        }

        @Override
        public String getEmailAddress() {
            return id.email;
        }

        @Override
        public String getPronoun() {
            return "OpenID";
        }
    }
}
