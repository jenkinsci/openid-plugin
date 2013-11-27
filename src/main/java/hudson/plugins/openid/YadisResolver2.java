package hudson.plugins.openid;

import org.openid4java.discovery.DiscoveryException;
import org.openid4java.discovery.yadis.YadisResolver;
import org.openid4java.discovery.yadis.YadisResult;
import org.openid4java.util.HttpCache;

import java.util.Set;

/**
 * {@link YadisResolver} with better error diagnosis.
 * @author Kohsuke Kawaguchi
 */
class YadisResolver2 extends YadisResolver {
    /**
     * Improve the error diagnosis by reporting which URL had failed. openid4java as of 0.9.4 does not do that.
     */
    @Override
    public YadisResult discover(String url, int maxRedirects, HttpCache cache, Set serviceTypes) throws DiscoveryException {
        try {
            return super.discover(url,maxRedirects,cache,serviceTypes);
        } catch (DiscoveryException e) {
            throw new DiscoveryException("Failed to discover XRDS document from "+url, e.getErrorCode(), e);
        }
    }
}