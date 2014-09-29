package hudson.plugins.openid;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.Hudson;
import hudson.security.SecurityRealm;
import org.kohsuke.stapler.DataBoundConstructor;
import org.openid4java.OpenIDException;
import org.openid4java.consumer.ConsumerException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.consumer.InMemoryConsumerAssociationStore;
import org.openid4java.consumer.InMemoryNonceVerifier;
import org.openid4java.discovery.Discovery;
import org.openid4java.discovery.DiscoveryException;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.discovery.Identifier;
import org.openid4java.discovery.UrlIdentifier;
import org.openid4java.server.RealmVerifierFactory;
import org.openid4java.util.HttpClientFactory;
import org.openid4java.util.HttpFetcherFactory;
import org.openid4java.util.ProxyProperties;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
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
        HttpFetcherFactory fetcherFactory = new HttpFetcherFactory();
        YadisResolver2 resolver = new YadisResolver2(fetcherFactory);
        ConsumerManager m = new ConsumerManager(new RealmVerifierFactory(resolver), new Discovery(), fetcherFactory);
        m.setAssociations(new InMemoryConsumerAssociationStore());
        m.setNonceVerifier(new InMemoryNonceVerifier(5000));
        m.setDiscovery(new Discovery() {
            /**
             * See http://www.slideshare.net/timdream/google-apps-account-as-openid for more details
             * why this is needed. Basically, once Google reports back that the user is actually http://mycorp.com/openid?id=12345,
             * the consumer still needs to try to resolve this ID to make sure that Google didn't return a bogus address
             * (say http://whitehouse.gov/barack_obama). This fails unless the web server of mycorp.com handles
             * GET to http://mycorp.com/openid?id=12345 properly, (which it doesn't most of the time.)
             *
             * The actual resource is in https://www.google.com/accounts/o8/user-xrds?uri=http://mycorp.com/openid?id=12345
             * so does Yadris lookup on that URL and pretend as if that came from http://mycorp.com/openid?id=12345
             */
            @Override
            public List discover(Identifier id) throws DiscoveryException {
                if (id.getIdentifier().startsWith("http://"+domain+'/') && id instanceof UrlIdentifier) {
                    String source = "https://www.google.com/accounts/o8/user-xrds?uri=" + id.getIdentifier();
                    List<DiscoveryInformation> r = super.discover(new UrlIdentifier(source));
                    List<DiscoveryInformation> x = new ArrayList<DiscoveryInformation>();
                    for (DiscoveryInformation discovered : r) {
                        if (discovered.getClaimedIdentifier().getIdentifier().equals(source)) {
                            discovered = new DiscoveryInformation(discovered.getOPEndpoint(),
                                    id,
                                    discovered.getDelegateIdentifier(),
                                    discovered.getVersion(),
                                    discovered.getTypes()
                            );
                        }
                        x.add(discovered);
                    }
                    return x;
                }
                return super.discover(id);
            }
        });
        m.getDiscovery().setYadisResolver(resolver);
        return m;
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<SecurityRealm> {
        public String getDisplayName() {
            return "Google Apps SSO (with OpenID)";
        }
    }

    private static final Logger LOGGER = Logger.getLogger(OpenIdSsoSecurityRealm.class.getName());
}
