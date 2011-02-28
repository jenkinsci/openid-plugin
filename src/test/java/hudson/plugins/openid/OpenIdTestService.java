/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package hudson.plugins.openid;

import com.cloudbees.openid4java.team.TeamExtensionFactory;
import com.cloudbees.openid4java.team.TeamExtensionRequest;
import com.cloudbees.openid4java.team.TeamExtensionResponse;
import com.google.common.base.Joiner;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.openid4java.association.AssociationException;
import org.openid4java.message.*;
import org.openid4java.message.ax.AxMessage;
import org.openid4java.message.ax.FetchRequest;
import org.openid4java.message.ax.FetchResponse;
import org.openid4java.message.sreg.SRegMessage;
import org.openid4java.message.sreg.SRegRequest;
import org.openid4java.message.sreg.SRegResponse;
import org.openid4java.server.InMemoryServerAssociationStore;
import org.openid4java.server.ServerException;
import org.openid4java.server.ServerManager;

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

        public void generateResponse(StaplerRequest req, StaplerResponse rsp, Object node) throws IOException, ServletException {
            rsp.setContentType("text/plain");
            rsp.getWriter().print(msg.keyValueFormEncoding());
        }
    }

    static class OperationFailure extends RuntimeException implements HttpResponse {
        public OperationFailure(String message) {
            super(message);
        }

        public void generateResponse(StaplerRequest req, StaplerResponse rsp, Object node) throws IOException, ServletException {
            rsp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,getMessage());
        }
    }


    public final String url;

    public final String endpointUrl;

    public Map<IdProperty,String> props;

    public final Set<String> teams;

    private final ServerManager manager;

    private final List<ProcessExtension> extensions;

    public enum IdProperty {
        email, nick, fullName, firstName, lastName, derivedFullName
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

    public String getUserIdentity() {
        return url + props.get(IdProperty.email);
    }
    
    public HttpResponse doEndpoint(StaplerRequest request) throws IOException {
        final ParameterList requestp = new ParameterList(request.getParameterMap());
        final String mode = requestp.getParameterValue("openid.mode");
        final String realm = getRealm(requestp);

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
            if (rsp instanceof  AuthSuccess) {
                try {
                    manager.sign((AuthSuccess)rsp);
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
            throw new OperationFailure("Unknown extend: "+mode);
        }
    }

    private String getRealm(ParameterList requestp) {
        final String realm = requestp.getParameterValue("openid.realm");
        final String returnTo = requestp.getParameterValue("openid.return_to");

        if (realm==null && returnTo!=null)
            try {
                return new URL(returnTo).getHost();
            } catch (MalformedURLException e) {
                // Fall back
                return returnTo;
            }
        
        return realm;
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

                    List<String> attrs = (List<String>)sregReq.getAttributes();
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

                    for (Map.Entry<String,String> e : ((Map<String,String>)fetchReq.getAttributes()).entrySet()) {
                        if ((e.getValue().equals("http://axschema.org/contact/email")
                        ||  e.getValue().equals("http://schema.openid.net/contact/email")) && s.props.containsKey(IdProperty.email))
                            fr.addAttribute(e.getKey(),e.getValue(),s.props.get(IdProperty.email));

                        if (e.getValue().equals("http://axschema.org/namePerson/first") && s.props.containsKey(IdProperty.firstName))
                            fr.addAttribute(e.getKey(),e.getValue(),s.props.get(IdProperty.firstName));

                        if (e.getValue().equals("http://axschema.org/namePerson/last") && s.props.containsKey(IdProperty.lastName))
                            fr.addAttribute(e.getKey(),e.getValue(),s.props.get(IdProperty.lastName));
                    }

                    rep.addExtension(fr);
                }
            }
        }
    };

    static final ProcessExtension TEAM_EXTENSION = new ProcessExtension() {

        public void process(OpenIdTestService s, AuthRequest authReq, Message rep) throws MessageException {
            if (authReq.hasExtension(TeamExtensionFactory.URI)) {
                MessageExtension ext = authReq.getExtension(TeamExtensionFactory.URI);
                if (ext instanceof TeamExtensionRequest) {
                    TeamExtensionRequest teamReq = (TeamExtensionRequest)ext;

                    rep.addExtension(new ServiceTeamExtensionResponse(s.teams));
                }
            }
        }
    };

    public void doDynamic(StaplerRequest req, StaplerResponse rsp) throws IOException, ServletException {
        req.getView(this, "xrds.jelly").forward(req, rsp);
    }

    static class ServiceTeamExtensionResponse extends TeamExtensionResponse {
        ServiceTeamExtensionResponse(Set<String> teams) {
            params.set(new Parameter("is_member", Joiner.on(',').join(teams)));
        }
    }
}
