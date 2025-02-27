package hudson.plugins.openid;

import org.junit.Test;
import org.junit.Before;
import org.jvnet.hudson.test.JenkinsRule;
import org.junit.Rule;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.HttpResponse;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.OpenIDException;
import javax.servlet.http.HttpSession;
import java.net.URL;
import java.net.MalformedURLException;
import java.io.IOException;
import static org.mockito.Mockito.*;
import static org.junit.Assert.*;

public class OpenIdSessionTest {

    @Rule
    public JenkinsRule j = new JenkinsRule();

    private TestableOpenIdSession session;
    private static final String ENDPOINT_URL = "http://example.com/openid";
    private StaplerRequest mockRequest;
    private HttpSession mockSession;

    // Create a concrete implementation of OpenIdSession for testing
    private static class TestableOpenIdSession extends OpenIdSession {
        private final StaplerRequest mockRequest;
        private boolean commenceLoginCalled = false;

        public TestableOpenIdSession(StaplerRequest request) throws OpenIDException, MalformedURLException {
            super(new ConsumerManager(), 
                  new DiscoveryInformation(new URL(ENDPOINT_URL)), 
                  "/finishLogin");
            this.mockRequest = request;
        }

        @Override
        public HttpResponse doFinishLogin(StaplerRequest request) {
            return null; // Not needed for these tests
        }

        @Override
        public HttpResponse onSuccess(Identity identity) {
            return null; // Not needed for these tests
        }

        @Override
        public HttpResponse doCommenceLogin() throws OpenIDException, IOException {
            if (mockRequest != null) {
                HttpSession session = mockRequest.getSession(false);
                if (session != null) {
                    session.invalidate();
                }
            }
            commenceLoginCalled = true;
            // Return dummy response instead of calling super
            return new HttpResponse() {
                @Override
                public void generateResponse(StaplerRequest req, org.kohsuke.stapler.StaplerResponse rsp, Object node) throws IOException {
                    // Do nothing for test
                }
            };
        }

        public boolean wasCommenceLoginCalled() {
            return commenceLoginCalled;
        }
    }

    @Before
    public void setUp() throws Exception {
        // Setup mocks
        mockRequest = mock(StaplerRequest.class);
        mockSession = mock(HttpSession.class);
        when(mockRequest.getSession()).thenReturn(mockSession);
        when(mockRequest.getSession(false)).thenReturn(mockSession);
        when(mockSession.getId()).thenReturn("session-id-1", "session-id-2");
    }

    @Test
    public void testDoCommenceLoginWithNullRequest() throws Exception {
        session = new TestableOpenIdSession(null);
        HttpResponse response = session.doCommenceLogin();
        
        assertNotNull("Response should not be null", response);
        assertTrue("CommenceLogin should have been called", session.wasCommenceLoginCalled());
        // No session invalidation should occur with null request
    }

    @Test
    public void testDoCommenceLoginWithValidRequest() throws Exception {
        session = new TestableOpenIdSession(mockRequest);
        
        String originalSessionId = mockSession.getId();
        
        HttpResponse response = session.doCommenceLogin();
        
        assertNotNull("Response should not be null", response);
        assertTrue("CommenceLogin should have been called", session.wasCommenceLoginCalled());
        
        String newSessionId = mockSession.getId();
        assertNotEquals("Session should have been invalidated", 
            originalSessionId, newSessionId);
        
        // Verify that invalidate was called
        verify(mockSession).invalidate();
    }
}
