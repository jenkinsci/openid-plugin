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

import com.cloudbees.openid4java.team.TeamExtensionFactory;
import com.cloudbees.openid4java.team.TeamExtensionRequest;
import com.cloudbees.openid4java.team.TeamExtensionResponse;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerRequest2;
import org.kohsuke.stapler.StaplerResponse2;
import org.openid4java.association.AssociationException;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.Message;
import org.openid4java.message.MessageException;
import org.openid4java.message.MessageExtension;
import org.openid4java.message.Parameter;
import org.openid4java.message.ParameterList;
import org.openid4java.message.ax.AxMessage;
import org.openid4java.message.ax.FetchRequest;
import org.openid4java.message.ax.FetchResponse;
import org.openid4java.message.sreg.SRegMessage;
import org.openid4java.message.sreg.SRegRequest;
import org.openid4java.message.sreg.SRegResponse;
import org.openid4java.server.InMemoryServerAssociationStore;
import org.openid4java.server.ServerException;
import org.openid4java.server.ServerManager;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 *
 * @author Kohsuke Kawaguchi
 * @author Paul Sandoz
 */
public class OpenIdTestService {

    static class MessageResponse implements HttpResponse {
        private final Message msg;

        public MessageResponse(Message msg) {
            this.msg = msg;
        }

        public void generateResponse(StaplerRequest2 req, StaplerResponse2 rsp, Object node) throws IOException {
            rsp.setContentType("text/plain");
            rsp.getWriter().print(msg.keyValueFormEncoding());
        }
    }

    static class OperationFailure extends RuntimeException implements HttpResponse {
        public OperationFailure(String message) {
            super(message);
        }

        public void generateResponse(StaplerRequest2 req, StaplerResponse2 rsp, Object node) throws IOException {
            rsp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, getMessage());
        }
    }


    public final String url;
    public final String endpointUrl;
    public Map<IdProperty, String> props;
    public final Set<String> teams;

    private final ServerManager manager;
    private final List<ProcessExtension> extensions;

    public enum IdProperty {
        email, email2, email3, nick, fullName, firstName, lastName, derivedFullName
    }

    OpenIdTestService(String url, Map<IdProperty, String> props, Set<String> teams, List<ProcessExtension> extensions) {
        this.url = url;
        this.endpointUrl = url + "endpoint";

        this.props = props;
        this.teams = teams;
        this.extensions = extensions;

        manager = new ServerManager();
        manager.setSharedAssociations(new InMemoryServerAssociationStore());
        manager.setPrivateAssociations(new InMemoryServerAssociationStore());
        manager.setOPEndpointUrl(endpointUrl);
    }

    /**
     * This method causes tests without emails to fail.
     * TODO: find alternative way to setup user identity.
     */
    public String getUserIdentity() {
        final String email;
        if (props.get(IdProperty.email) != null) {
            email = props.get(IdProperty.email);
        } else if (props.get(IdProperty.email2) != null) {
            email = props.get(IdProperty.email2);
        } else {
            email = props.get(IdProperty.email3);
        }
        return url + email;
    }

    public HttpResponse doEndpoint(StaplerRequest2 request) throws IOException {
        final ParameterList requestp = new ParameterList(request.getParameterMap());
        final String mode = requestp.getParameterValue("openid.mode");

        if ("associate".equals(mode)) {
            // --- process an association extend ---
            return new MessageResponse(manager.associationResponse(requestp));
        } else if ("checkid_setup".equals(mode) || "checkid_immediate".equals(mode)) {

            // No need to redirect to a page with an HTML form
            // Skip the authentication step

            String identity = getUserIdentity();
            Message rsp = manager.authResponse(requestp, identity, identity, true, false);
            try {
                respondToExtensions(requestp, rsp);
            } catch (MessageException ex) {
                throw new OperationFailure(ex.getMessage());
            }

            // Need to sign after because SReg extension parameters are signed by openid4java
            if (rsp instanceof AuthSuccess) {
                try {
                    manager.sign((AuthSuccess) rsp);
                } catch (ServerException e) {
                    throw new OperationFailure(e.getMessage());
                } catch (AssociationException e) {
                    throw new OperationFailure(e.getMessage());
                }
            }

            return new HttpRedirect(rsp.getDestinationUrl(true));
        } else if ("check_authentication".equals(mode)) {
            return new MessageResponse(manager.verify(requestp));
        } else {
            throw new OperationFailure("Unknown extend: " + mode);
        }
    }

    private void respondToExtensions(ParameterList reqp, Message rep) throws MessageException {
        AuthRequest authReq = AuthRequest.createAuthRequest(reqp, manager.getRealmVerifier());

        for (ProcessExtension e : extensions) {
            e.process(this, authReq, rep);
        }
    }

    public interface ProcessExtension {
        void process(OpenIdTestService s, AuthRequest authReq, Message rep) throws MessageException;
    }

    static final ProcessExtension SREG_EXTENSION = new ProcessExtension() {

        public void process(OpenIdTestService s, AuthRequest authReq, Message rep) throws MessageException {
            if (authReq.hasExtension(SRegMessage.OPENID_NS_SREG)) {
                MessageExtension ext = authReq.getExtension(SRegMessage.OPENID_NS_SREG);
                if (ext instanceof SRegRequest) {
                    SRegRequest sregReq = (SRegRequest) ext;
                    SRegResponse sregRes = SRegResponse.createFetchResponse();

                    List<String> attrs = (List<String>) sregReq.getAttributes();
                    if (attrs.contains("fullname") && s.props.containsKey(IdProperty.fullName)) {
                        sregRes.addAttribute("fullname", s.props.get(IdProperty.fullName));
                    }

                    if (attrs.contains("nickname") && s.props.containsKey(IdProperty.nick)) {
                        sregRes.addAttribute("nickname", s.props.get(IdProperty.nick));
                    }

                    if (attrs.contains("email") && s.props.containsKey(IdProperty.email)) {
                        sregRes.addAttribute("email", s.props.get(IdProperty.email));
                    }

                    rep.addExtension(sregRes);
                }
            }
        }
    };

    static final ProcessExtension AX_EXTENSION = new ProcessExtension() {

        public void process(OpenIdTestService s, AuthRequest authReq, Message rep) throws MessageException {
            if (authReq.hasExtension(AxMessage.OPENID_NS_AX)) {
                MessageExtension ext = authReq.getExtension(AxMessage.OPENID_NS_AX);
                if (ext instanceof FetchRequest) {
                    FetchRequest fetchReq = (FetchRequest) ext;
                    FetchResponse fr = FetchResponse.createFetchResponse();

                    for (Map.Entry<String, String> e : ((Map<String, String>) fetchReq.getAttributes()).entrySet()) {
                        if ((e.getValue().equals("http://axschema.org/contact/email")) && s.props.containsKey(IdProperty.email)) {
                            if (s.props.get(IdProperty.email) != null) {
                                fr.addAttribute(e.getKey(), e.getValue(), s.props.get(IdProperty.email));
                            }
                        } else if ((e.getValue().equals("http://schema.openid.net/contact/email")) && s.props.containsKey(IdProperty.email2)) {
                            if (s.props.get(IdProperty.email2) != null) {
                                fr.addAttribute(e.getKey(), e.getValue(), s.props.get(IdProperty.email2));
                            }
                        } else if ((e.getValue().equals("http://openid.net/schema/contact/email")) && s.props.containsKey(IdProperty.email3)) {
                            if (s.props.get(IdProperty.email3) != null) {
                                fr.addAttribute(e.getKey(), e.getValue(), s.props.get(IdProperty.email3));
                            }
                        }

                        if (e.getValue().equals("http://axschema.org/namePerson/first") && s.props.containsKey(IdProperty.firstName)) {
                            fr.addAttribute(e.getKey(), e.getValue(), s.props.get(IdProperty.firstName));
                        }

                        if (e.getValue().equals("http://axschema.org/namePerson/last") && s.props.containsKey(IdProperty.lastName)) {
                            fr.addAttribute(e.getKey(), e.getValue(), s.props.get(IdProperty.lastName));
                        }
                    }

                    rep.addExtension(fr);
                }
            }
        }
    };

    static final ProcessExtension TEAM_EXTENSION = (s, authReq, rep) -> {
        if (authReq.hasExtension(TeamExtensionFactory.URI)) {
            MessageExtension ext = authReq.getExtension(TeamExtensionFactory.URI);
            if (ext instanceof TeamExtensionRequest) {
                rep.addExtension(new ServiceTeamExtensionResponse(s.teams));
            }
        }
    };

    public void doDynamic(StaplerRequest2 req, StaplerResponse2 rsp) throws IOException, ServletException {
        try {
            req.getView(this, "xrds.jelly").forward(req, rsp);
        } catch (jakarta.servlet.ServletException | IOException e) {
            e.printStackTrace();
        }
    }

    static class ServiceTeamExtensionResponse extends TeamExtensionResponse {
        ServiceTeamExtensionResponse(Set<String> teams) {
            params.set(new Parameter("is_member", String.join(",", teams)));
        }
    }
}
