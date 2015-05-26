package com.dotmarketing.filters.cas;

import com.dotmarketing.util.Config;
import com.dotmarketing.util.SecurityLogger;
import com.liferay.portal.PortalException;
import com.liferay.portal.SystemException;
import com.liferay.portal.ejb.UserManagerUtil;
import com.liferay.portal.model.Company;
import com.liferay.portal.util.CookieKeys;
import com.liferay.portal.util.PortalUtil;
import com.liferay.portal.util.WebKeys;
import com.liferay.util.CookieUtil;
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

public class CasBackendLoginFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;
        HttpSession session = request.getSession(false);

        if (session == null
                || session.getAttribute(WebKeys.USER_ID) != null
                || session.getAttribute(AbstractCasFilter.CONST_CAS_ASSERTION) == null) {
            chain.doFilter(request, response);
            return;
        }

        Object casAssertion = session.getAttribute(AbstractCasFilter.CONST_CAS_ASSERTION);
        AttributePrincipal principal = ((Assertion) casAssertion).getPrincipal();
        String username = principal.getName();

        doLogin(username, request, response, session);

        request.getRequestDispatcher("/html/portal/touch_protected.jsp").forward(request, response);
    }

    private void doLogin(String username, HttpServletRequest request, HttpServletResponse response, HttpSession session) {
        // see LoginAction
        try {
            String userId = username;
            Company company = PortalUtil.getCompany(request);
            boolean rememberMe = false;

            if (company.getAuthType().equals(Company.AUTH_TYPE_EA)) {
                userId = UserManagerUtil.getUserId(company.getCompanyId(), username);
            }
            session.setAttribute(WebKeys.USER_ID, userId);

            String secure = Config.getStringProperty("COOKIES_SECURE_FLAG", "https").equals("always")
                    || (Config.getStringProperty("COOKIES_SECURE_FLAG", "https").equals("https") && request.isSecure()) ? CookieUtil.SECURE : "";

            String httpOnly = Config.getBooleanProperty("COOKIES_HTTP_ONLY", false) ? CookieUtil.HTTP_ONLY : "";

            String maxAge = rememberMe ? "31536000" : "0";

            StringBuilder headerStr = new StringBuilder();
            headerStr.append(CookieKeys.ID).append("=\"").append(UserManagerUtil.encryptUserId(userId)).append("\";")
                    .append(secure).append(";").append(httpOnly).append(";Path=/").append(";Max-Age=").append(maxAge);
            response.addHeader("SET-COOKIE", headerStr.toString());

        } catch (PortalException | SystemException e) {
            SecurityLogger.logInfo(CasBackendLoginFilter.class, "Exception caught: " + e.getMessage());
        }
    }

    @Override
    public void destroy() {
    }
}
