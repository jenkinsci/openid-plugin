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
package hudson.plugins.openid.impl;

import hudson.Extension;
import hudson.plugins.openid.Identity;
import hudson.plugins.openid.OpenIdExtension;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.MessageException;
import org.openid4java.message.ax.AxMessage;
import org.openid4java.message.ax.FetchRequest;
import org.openid4java.message.ax.FetchResponse;
import org.openid4java.message.sreg.SRegMessage;
import org.openid4java.message.sreg.SRegRequest;
import org.openid4java.message.sreg.SRegResponse;

/**
 * @author Paul Sandoz
 */
@Extension
public class UserInfoExtension extends OpenIdExtension {
	
	@Override 
	public void extendFetch(FetchRequest fetch) throws MessageException {
		fetch.addAttribute("email", "http://schema.openid.net/contact/email", true);
	    fetch.addAttribute("firstName", "http://axschema.org/namePerson/first", true);
	    fetch.addAttribute("lastName", "http://axschema.org/namePerson/last", true);
	    fetch.addAttribute("ff", "http://axschema.org/namePerson", false);
	    fetch.addAttribute("img", "http://axschema.org/media/image/default/", false);
	}
	
    @Override
    public void extend(AuthRequest authRequest) throws MessageException {
        // extend some user information
        // see http://code.google.com/apis/accounts/docs/OpenID.html
        SRegRequest sregReq = SRegRequest.createFetchRequest();
        sregReq.addAttribute("fullname", true);
        sregReq.addAttribute("nickname", true);
        sregReq.addAttribute("email", true);
        authRequest.addExtension(sregReq);
    }

    @Override
    public void process(AuthSuccess authSuccess, Identity id) throws MessageException {
        SRegResponse sr = getMessageAs(SRegResponse.class,  authSuccess, SRegMessage.OPENID_NS_SREG);
        id.setNick(sr.getAttributeValue("nickname"));
        String fullName = sr.getAttributeValue("fullname");
        String email = sr.getAttributeValue("email");

        try {
            FetchResponse fr = getMessageAs(FetchResponse.class,  authSuccess, AxMessage.OPENID_NS_AX);
            if (fr!=null) {
                if (fullName==null) {
                    String first = fr.getAttributeValue("firstName");
                    String last = fr.getAttributeValue("lastName");
                    if (first!=null & last!=null)
                        fullName = first+" "+last;
                }
                if (email==null)
                    email = fr.getAttributeValue("email");
            }
        } catch (MessageException e) {
            // if the process doesn't contain AX information, ignore. Maybe this is a bug in openid4java?
            // "0x100: Invalid value for attribute exchange mode: null"
        }
        id.setFullName(fullName);
        id.setEmail(email);
    }
}
