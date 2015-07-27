package com.dotmarketing.filters.cas;

import java.lang.Exception;
import java.util.Date;
import com.liferay.portal.util.PortalUtil;
import com.dotmarketing.business.APILocator;
import com.dotmarketing.exception.DotDataException;
import com.dotmarketing.exception.DotSecurityException;
import com.dotmarketing.util.SecurityLogger;
import com.dotmarketing.util.WebKeys;
import com.liferay.portal.model.Company;
import com.liferay.portal.model.User;
import org.jasig.cas.client.authentication.AttributePrincipal;
import org.jasig.cas.client.util.AbstractCasFilter;
import org.jasig.cas.client.validation.Assertion;
import com.liferay.portal.NoSuchUserException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import com.liferay.portal.ejb.UserManagerFactory;
import com.liferay.portal.PortalException;
import com.liferay.portal.SystemException;
import java.rmi.RemoteException;
import com.liferay.portal.ejb.UserLocalManagerUtil;

public class CasFrontendLoginFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;
        HttpSession session = request.getSession(false);

        if (session == null
                || session.getAttribute(WebKeys.CMS_USER) != null
                || session.getAttribute(AbstractCasFilter.CONST_CAS_ASSERTION) == null) {
            chain.doFilter(request, response);
            return;
        }

        Object casAssertion = session.getAttribute(AbstractCasFilter.CONST_CAS_ASSERTION);
        AttributePrincipal principal = ((Assertion) casAssertion).getPrincipal();

        doLogin(principal, request, response, session);

        String redirectUrl = (String) session.getAttribute(WebKeys.REDIRECT_AFTER_LOGIN);
        String referrerUrl = request.getParameter("referrer");
        if (redirectUrl != null) {
            session.removeAttribute(WebKeys.REDIRECT_AFTER_LOGIN);
            response.sendRedirect(redirectUrl);
        } else if (referrerUrl != null) {
            response.sendRedirect(referrerUrl);
        } else {
            chain.doFilter(request, response);
        }
    }

    private void doLogin(AttributePrincipal principal, HttpServletRequest request, HttpServletResponse response, HttpSession session) {
        try {
            String email = principal.getName();
            Company company = PortalUtil.getCompany(request);

            User user = null;
            if (!APILocator.getUserAPI().userExistsWithEmail(email))
            {
                user = UserLocalManagerUtil.addUser(company.getCompanyId(), true, "", true, "", "", false, principal.getAttributes().get("name").toString(), "", "", "", true, new Date(), email, company.getLocale());
                APILocator.getRoleAPI().addRoleToUser(request.getServletContext().getInitParameter("default_role_id"), user);
            }
            else{
                user = APILocator.getUserAPI().loadByUserByEmail(email, APILocator.getUserAPI().getSystemUser(), false);
                if (!user.getFirstName().equals(principal.getAttributes().get("name").toString())){
                    user.setFirstName(principal.getAttributes().get("name").toString());
                    UserLocalManagerUtil.updateUser(user);
                }
            }

            session.setAttribute(WebKeys.CMS_USER, user);
            SecurityLogger.logInfo(CasFrontendLoginFilter.class, "User " + email + " has sucessfully login from IP: " + request.getRemoteAddr());

        } catch (SystemException | PortalException | DotDataException | DotSecurityException e) {
            SecurityLogger.logInfo(CasFrontendLoginFilter.class, "Exception caught: " + e.getMessage());
        }
    }

    @Override
    public void destroy() {
    }

}
