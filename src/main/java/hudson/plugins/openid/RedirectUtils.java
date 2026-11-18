/*
 * The MIT License
 *
 * Copyright (c) 2004-2009, Sun Microsystems, Inc., Kohsuke Kawaguchi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package hudson.plugins.openid;

import java.net.URI;
import jenkins.model.Jenkins;

/**
 * Validates URLs that the plugin redirects to after a successful login.
 * <p>
 * Only same-origin targets are allowed, so a crafted {@code from} parameter
 * cannot turn the login endpoints into an open redirect (SECURITY-2997 /
 * CVE-2023-24445).
 */
final class RedirectUtils {

    private RedirectUtils() {}

    static boolean isSafeRedirectTarget(String url) {
        return isSafeRedirectTarget(url, Jenkins.get().getRootUrl());
    }

    static boolean isSafeRedirectTarget(String url, String rootUrl) {
        if (url == null) {
            return false;
        }

        String target = url.trim();
        if (target.isEmpty()) {
            return false;
        }

        // Backslashes are never part of a legitimate same-origin redirect and
        // can be used to smuggle a protocol-relative URL past prefix checks
        // (e.g. "/\evil.com" becomes "//evil.com" in some browsers).
        if (target.indexOf('\\') >= 0 || target.startsWith("//")) {
            return false;
        }

        URI uri;
        try {
            uri = URI.create(target);
        } catch (IllegalArgumentException e) {
            return false;
        }

        // No scheme and no authority: a same-origin path such as "/job/foo".
        if (uri.getScheme() == null && uri.getAuthority() == null) {
            return target.startsWith("/");
        }

        // An absolute URL (https://…) or any URL carrying an authority. Only
        // allow it when it points back at this Jenkins instance.
        if (rootUrl == null) {
            return false;
        }
        try {
            return sameOrigin(uri, URI.create(rootUrl));
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Picks a safe post-login redirect target.
     * <p>
     * The explicit {@code from} parameter wins when it is a safe target,
     * otherwise a same-origin {@code Referer} is used, and finally the Jenkins
     * root URL.
     *
     * @param from    the requested redirect target, may be {@code null}
     * @param referer the value of the {@code Referer} header, may be {@code null}
     * @param rootUrl the Jenkins root URL, may be {@code null}
     * @return a safe target, never {@code null}
     */
    static String safeRedirectTarget(String from, String referer, String rootUrl) {
        String target = safeCandidate(from, rootUrl);
        if (target != null) {
            return target;
        }
        target = safeCandidate(referer, rootUrl);
        if (target != null) {
            return target;
        }
        return rootUrl != null ? rootUrl : "/";
    }

    private static String safeCandidate(String candidate, String rootUrl) {
        if (candidate == null) {
            return null;
        }
        String target = candidate.trim();
        return isSafeRedirectTarget(target, rootUrl) ? target : null;
    }

    private static boolean sameOrigin(URI candidate, URI root) {
        String scheme = candidate.getScheme();
        String host = candidate.getHost();
        return scheme != null
                && host != null
                && scheme.equalsIgnoreCase(root.getScheme())
                && host.equalsIgnoreCase(root.getHost())
                && effectivePort(candidate) == effectivePort(root);
    }

    private static int effectivePort(URI uri) {
        int port = uri.getPort();
        if (port != -1) {
            return port;
        }
        if ("https".equalsIgnoreCase(uri.getScheme())) {
            return 443;
        }
        if ("http".equalsIgnoreCase(uri.getScheme())) {
            return 80;
        }
        return -1;
    }
}
