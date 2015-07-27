package com.dotmarketing.filters.cas;

import java.lang.Exception;
import java.util.Date;
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
import com.liferay.portal.model.User;
import com.dotmarketing.business.APILocator;
import com.dotmarketing.exception.DotDataException;
import com.dotmarketing.exception.DotSecurityException;
import java.rmi.RemoteException;
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
import com.liferay.portal.ejb.UserLocalManagerUtil;

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

        doLogin(principal, request, response, session);

        request.getRequestDispatcher("/html/portal/touch_protected.jsp").forward(request, response);
    }

    private void doLogin(AttributePrincipal principal, HttpServletRequest request, HttpServletResponse response, HttpSession session) {
        // see LoginAction
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

            session.setAttribute(WebKeys.USER_ID, user.getUserId());

            String secure = Config.getStringProperty("COOKIES_SECURE_FLAG", "https").equals("always")
                    || (Config.getStringProperty("COOKIES_SECURE_FLAG", "https").equals("https") && request.isSecure()) ? CookieUtil.SECURE : "";

            String httpOnly = Config.getBooleanProperty("COOKIES_HTTP_ONLY", false) ? CookieUtil.HTTP_ONLY : "";

            boolean rememberMe = false;
            String maxAge = rememberMe ? "31536000" : "0";

            StringBuilder headerStr = new StringBuilder();
            headerStr.append(CookieKeys.ID).append("=\"").append(UserManagerUtil.encryptUserId(user.getUserId())).append("\";")
                    .append(secure).append(";").append(httpOnly).append(";Path=/").append(";Max-Age=").append(maxAge);
            response.addHeader("SET-COOKIE", headerStr.toString());

        } catch (DotSecurityException | DotDataException | PortalException | SystemException e) {
            SecurityLogger.logInfo(CasBackendLoginFilter.class, "Exception caught: " + e.getMessage());
        }
    }

    @Override
    public void destroy() {
    }
}
