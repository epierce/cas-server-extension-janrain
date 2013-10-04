package edu.usf.cims.cas.support.janrain.web.flow;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.validation.constraints.NotNull;

import org.apache.commons.lang.StringUtils;
import org.jasig.cas.CentralAuthenticationService;
import org.jasig.cas.authentication.principal.Service;
import org.jasig.cas.ticket.TicketException;
import org.jasig.cas.web.support.WebUtils;

import edu.usf.cims.cas.support.janrain.authentication.principal.JanrainCredentials;

import org.springframework.webflow.action.AbstractAction;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * This class represents an action in the webflow to retrieve user information from the Janrain Engage service. If the token 
 * parameter exists in the web request, it is used to create a new JanrainCredential.
 *
 * @author Eric Pierce
 * @since 0.1
 */
public final class JanrainAuthAction extends AbstractAction {

    private static final String TOKEN_PARAMETER = "token";

    @NotNull
    private CentralAuthenticationService centralAuthenticationService;

    @Override
    protected Event doExecute(RequestContext context) throws Exception {
        HttpServletRequest request = WebUtils.getHttpServletRequest(context);
        HttpSession session = request.getSession();

        // get token value
        String tokenValue = request.getParameter(TOKEN_PARAMETER);

        // Token exists, authenticate it with Janrain
        if (StringUtils.isNotBlank(tokenValue)) {

            // get credential
            @SuppressWarnings("unchecked")
            JanrainCredentials credential = new JanrainCredentials(tokenValue);

            // retrieve service from session and put it into webflow
            Service service = (Service) session.getAttribute("service");
            context.getFlowScope().put("service", service);

            try {
                WebUtils.putTicketGrantingTicketInRequestScope(context, this.centralAuthenticationService
                    .createTicketGrantingTicket(credential));
                return success();
            } catch (final TicketException e) {
                return error();
            }
        } else {
            // put service in session from flow scope
            Service service = (Service) context.getFlowScope().get("service");
            session.setAttribute("service", service);
        }

        return error();
    }

    public void setCentralAuthenticationService(CentralAuthenticationService centralAuthenticationService) {
        this.centralAuthenticationService = centralAuthenticationService;
    }
}