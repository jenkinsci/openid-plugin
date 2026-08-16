package hudson.plugins.openid;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerRequest2;
import org.kohsuke.stapler.StaplerResponse2;
import org.openid4java.OpenIDException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.discovery.DiscoveryInformation;

@WithJenkins
public class OpenIdSessionTest {

    private TestableOpenIdSession session;
    private static final String ENDPOINT_URL = "http://example.com/openid";
    private StaplerRequest2 mockRequest;
    private HttpSession mockSession;

    // Create a concrete implementation of OpenIdSession for testing
    private static class TestableOpenIdSession extends OpenIdSession {
        private final StaplerRequest2 mockRequest;
        private boolean commenceLoginCalled = false;

        public TestableOpenIdSession(StaplerRequest2 request) throws OpenIDException, MalformedURLException {
            super(new ConsumerManager(), new DiscoveryInformation(new URL(ENDPOINT_URL)), "/finishLogin");
            this.mockRequest = request;
        }

        @Override
        public HttpResponse doFinishLogin(StaplerRequest2 request) {
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
                public void generateResponse(StaplerRequest2 req, StaplerResponse2 rsp, Object node)
                        throws IOException {
                    // Do nothing for test
                }
            };
        }

        public boolean wasCommenceLoginCalled() {
            return commenceLoginCalled;
        }
    }

    @BeforeEach
    public void setUp() {
        // Setup mocks
        mockRequest = mock(StaplerRequest2.class);
        mockSession = mock(HttpSession.class);
        when(mockRequest.getSession()).thenReturn(mockSession);
        when(mockRequest.getSession(false)).thenReturn(mockSession);
        when(mockSession.getId()).thenReturn("session-id-1", "session-id-2");
    }

    @Test
    public void testDoCommenceLoginWithNullRequest(JenkinsRule j) throws Exception {
        session = new TestableOpenIdSession(null);
        HttpResponse response = session.doCommenceLogin();

        assertNotNull(response, "Response should not be null");
        assertTrue(session.wasCommenceLoginCalled(), "CommenceLogin should have been called");
        // No session invalidation should occur with null request
    }

    @Test
    public void testDoCommenceLoginWithValidRequest(JenkinsRule j) throws Exception {
        session = new TestableOpenIdSession(mockRequest);

        String originalSessionId = mockSession.getId();

        HttpResponse response = session.doCommenceLogin();

        assertNotNull(response, "Response should not be null");
        assertTrue(session.wasCommenceLoginCalled(), "CommenceLogin should have been called");

        String newSessionId = mockSession.getId();
        assertNotEquals(originalSessionId, newSessionId, "Session should have been invalidated");

        // Verify that invalidate was called
        verify(mockSession).invalidate();
    }
}
