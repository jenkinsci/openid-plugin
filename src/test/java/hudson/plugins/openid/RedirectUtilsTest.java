package hudson.plugins.openid;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class RedirectUtilsTest {

    private static final String ROOT = "https://jenkins.example.com/jenkins/";

    @Test
    void rejectsMissingOrBlankTargets() {
        assertFalse(RedirectUtils.isSafeRedirectTarget(null, ROOT));
        assertFalse(RedirectUtils.isSafeRedirectTarget("", ROOT));
        assertFalse(RedirectUtils.isSafeRedirectTarget("   ", ROOT));
    }

    @Test
    void rejectsProtocolRelativeAndBackslashTargets() {
        assertFalse(RedirectUtils.isSafeRedirectTarget("//evil.example.com/", ROOT));
        assertFalse(RedirectUtils.isSafeRedirectTarget("/\\evil.example.com/", ROOT));
        assertFalse(RedirectUtils.isSafeRedirectTarget("\\\\evil.example.com/", ROOT));
    }

    @Test
    void rejectsExternalAbsoluteTargets() {
        assertFalse(RedirectUtils.isSafeRedirectTarget("https://evil.example.com/", ROOT));
        assertFalse(RedirectUtils.isSafeRedirectTarget("http://jenkins.example.com/", ROOT));
        assertFalse(RedirectUtils.isSafeRedirectTarget("https://jenkins.example.com:8443/", ROOT));
        assertFalse(RedirectUtils.isSafeRedirectTarget("https://jenkins.example.com.evil.example.com/", ROOT));
        assertFalse(RedirectUtils.isSafeRedirectTarget("https://jenkins.example.com@evil.example.com/", ROOT));
        assertFalse(RedirectUtils.isSafeRedirectTarget("javascript:alert(document.domain)", ROOT));
        assertFalse(RedirectUtils.isSafeRedirectTarget("data:text/html,<script>alert(1)</script>", ROOT));
    }

    @Test
    void acceptsSameOriginPathsAndUrls() {
        assertTrue(RedirectUtils.isSafeRedirectTarget("/job/example/", ROOT));
        assertTrue(RedirectUtils.isSafeRedirectTarget("  /job/example/  ", ROOT));
        assertTrue(RedirectUtils.isSafeRedirectTarget("https://jenkins.example.com/job/example/", ROOT));
        assertTrue(RedirectUtils.isSafeRedirectTarget("https://JENKINS.example.com/job/example/", ROOT));
        assertTrue(RedirectUtils.isSafeRedirectTarget("https://jenkins.example.com:443/job/example/", ROOT));
    }

    @Test
    void absoluteTargetsNeedAKnownRootUrl() {
        assertFalse(RedirectUtils.isSafeRedirectTarget("https://jenkins.example.com/job/example/", null));
        assertTrue(RedirectUtils.isSafeRedirectTarget("/job/example/", null));
    }

    @Test
    void safeRedirectTargetPrefersTheExplicitTarget() {
        assertEquals(
                "/job/example/",
                RedirectUtils.safeRedirectTarget("/job/example/", "https://jenkins.example.com/other/", ROOT));
    }

    @Test
    void safeRedirectTargetFallsBackToSameOriginReferer() {
        assertEquals(
                "https://jenkins.example.com/other/",
                RedirectUtils.safeRedirectTarget("//evil.example.com/", "https://jenkins.example.com/other/", ROOT));
    }

    @Test
    void safeRedirectTargetRejectsExternalReferer() {
        assertEquals(ROOT, RedirectUtils.safeRedirectTarget(null, "https://evil.example.com/", ROOT));
        assertEquals(ROOT, RedirectUtils.safeRedirectTarget("//evil.example.com/", "https://evil.example.com/", ROOT));
    }

    @Test
    void safeRedirectTargetFallsBackToTheRootUrl() {
        assertEquals(ROOT, RedirectUtils.safeRedirectTarget(null, null, ROOT));
        assertEquals("/", RedirectUtils.safeRedirectTarget(null, null, null));
    }
}
