package hudson.plugins.openid;

import com.cloudbees.openid4java.team.TeamExtensionFactory;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.security.SecurityRealm;
import org.kohsuke.stapler.DataBoundConstructor;
import org.openid4java.OpenIDException;
import org.openid4java.association.AssociationException;
import org.openid4java.consumer.ConsumerException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.consumer.VerificationResult;
import org.openid4java.discovery.DiscoveryException;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.discovery.UrlIdentifier;
import org.openid4java.message.AuthFailure;
import org.openid4java.message.AuthImmediateFailure;
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.MessageException;
import org.openid4java.message.ParameterList;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.logging.Logger;

/**
 * {@link OpenIdSsoSecurityRealm} with Google Apps.
 *
 * @author Kohsuke Kawaguchi
 */
public class GoogleAppSsoSecurityRealm extends OpenIdSsoSecurityRealm {
    public final String domain;

    @DataBoundConstructor
    public GoogleAppSsoSecurityRealm(String domain) throws IOException, OpenIDException {
        super("https://www.google.com/accounts/o8/site-xrds?hd="+domain);
        this.domain = domain;
    }

    @Override
    protected ConsumerManager createManager() throws ConsumerException {
        return new ConsumerManager() {
            /**
             * Ideally we'd just like to override the verifyDiscovered() method
             * and check that the claimed identity is in the domain. But openid4java
             * makes those methods private, so I work around that by copying the verify method instead.
             *
             * See http://www.slideshare.net/timdream/google-apps-account-as-openid for more details
             * why this is needed. Basically, once Google reports back that the user is actually http://mycorp.com/openid?id=12345,
             * the consumer still needs to try to resolve this ID to make sure that Google didn't return a bogus address
             * (say http://whitehouse.gov/barack_obama). This fails unless the web server of mycorp.com handles
             * that properly, (which it doesn't most of the time.)
             *
             * So in this patch, we just skip that verification phase.
             */
            public VerificationResult verify(String receivingUrl,
                                             ParameterList response,
                                             DiscoveryInformation discovered)
                    throws MessageException, DiscoveryException, AssociationException
            {
                VerificationResult result = new VerificationResult();
//                        _log.info("Verifying authentication response...");

                // non-immediate negative response
                if ( "cancel".equals(response.getParameterValue("openid.mode")) )
                {
                    result.setAuthResponse(AuthFailure.createAuthFailure(response));
//                            _log.info("Received auth failure.");
                    return result;
                }

                // immediate negative response
                if ( "setup_needed".equals(response.getParameterValue("openid.mode")) ||
                        ("id_res".equals(response.getParameterValue("openid.mode"))
                        && response.hasParameter("openid.user_setup_url") ) )
                {
                    AuthImmediateFailure fail =
                            AuthImmediateFailure.createAuthImmediateFailure(response);
                    result.setAuthResponse(fail);
                    result.setOPSetupUrl(fail.getUserSetupUrl());
//                            _log.info("Received auth immediate failure.");
                    return result;
                }

                AuthSuccess authResp = AuthSuccess.createAuthSuccess(response);
//                        LOGGER.("Received positive auth response.");

                authResp.validate();

                result.setAuthResponse(authResp);

                // [1/4] return_to verification
                if (! verifyReturnTo(receivingUrl, authResp))
                {
                    result.setStatusMsg("Return_To URL verification failed.");
                    LOGGER.severe("Return_To URL verification failed.");
                    return result;
                }

                // [2/4] : discovered info verification
//                        discovered = verifyDiscovered(authResp, discovered);

                // instead of verifyDiscovered, just trust what Google told us
                discovered = new DiscoveryInformation(discovered.getOPEndpoint(),
                        new UrlIdentifier(authResp.getIdentity()),
                        discovered.getDelegateIdentifier(),
                        discovered.getVersion(),
                        discovered.getTypes()
                );
                if (discovered == null || ! discovered.hasClaimedIdentifier())
                {
                    result.setStatusMsg("Discovered information verification failed.");
                    LOGGER.severe("Discovered information verification failed.");
                    return result;
                }

                // [3/4] : nonce verification
                if (! verifyNonce(authResp, discovered))
                {
                    result.setStatusMsg("Nonce verification failed.");
                    LOGGER.severe("Nonce verification failed.");
                    return result;
                }

                // [4/4] : signature verification
//                        return (verifySignature(authResp, discovered, result));
                try {
                    Method m = getClass().getSuperclass().getDeclaredMethod("verifySignature", AuthSuccess.class, DiscoveryInformation.class, VerificationResult.class);
                    m.setAccessible(true);
                    return (VerificationResult)m.invoke(this, authResp, discovered, result);
                } catch (NoSuchMethodException e) {
                    throw new Error(e);
                } catch (IllegalAccessException e) {
                    throw new Error(e);
                } catch (InvocationTargetException e) {
                    throw new Error(e);
                }
            }
        };
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<SecurityRealm> {
        public String getDisplayName() {
            return "Google Apps SSO (with OpenID)";
        }
    }

    private static final Logger LOGGER = Logger.getLogger(OpenIdSsoSecurityRealm.class.getName());
}
