package com.dotmarketing.filters.cas;

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
        String username = principal.getName();

        doLogin(username, request, response, session);

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

    private void doLogin(String username, HttpServletRequest request, HttpServletResponse response, HttpSession session) {
        User user;
        Company comp = com.dotmarketing.cms.factories.PublicCompanyFactory.getDefaultCompany();

        try {
            if (comp.getAuthType().equals(Company.AUTH_TYPE_EA)) {
                user = APILocator.getUserAPI().loadByUserByEmail(username, APILocator.getUserAPI().getSystemUser(), false);
            } else {
                user = APILocator.getUserAPI().loadUserById(username, APILocator.getUserAPI().getSystemUser(), false);
            }

            session.setAttribute(WebKeys.CMS_USER, user);
            SecurityLogger.logInfo(CasFrontendLoginFilter.class, "User " + username + " has sucessfully login from IP: " + request.getRemoteAddr());

        } catch (DotDataException | DotSecurityException e) {
            SecurityLogger.logInfo(CasFrontendLoginFilter.class, "Exception caught: " + e.getMessage());
        }
    }

    @Override
    public void destroy() {
    }

}
