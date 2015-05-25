package com.dotmarketing.filters;

import com.dotmarketing.cms.factories.PublicEncryptionFactory;
import com.dotmarketing.cms.login.factories.LoginFactory;
import com.dotmarketing.util.WebKeys;
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

public class CasLoginFilter implements Filter {

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
        LoginFactory.doCookieLogin(PublicEncryptionFactory.encryptString(username), request, response);

        String redirectUrl = (String) session.getAttribute(WebKeys.REDIRECT_AFTER_LOGIN);
        if (redirectUrl != null) {
            session.removeAttribute(WebKeys.REDIRECT_AFTER_LOGIN);
            response.sendRedirect(redirectUrl);
        } else {
            chain.doFilter(request, response);
        }
    }

    @Override
    public void destroy() {

    }
}
