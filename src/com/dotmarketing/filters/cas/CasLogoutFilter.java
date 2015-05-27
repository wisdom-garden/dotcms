package com.dotmarketing.filters.cas;

import org.jasig.cas.client.util.AbstractCasFilter;
import org.jasig.cas.client.util.CommonUtils;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class CasLogoutFilter extends AbstractCasFilter {

    private String casServerLogoutUrl;

    @Override
    protected void initInternal(FilterConfig filterConfig) throws ServletException {
        if (!isIgnoreInitConfiguration()) {
            super.initInternal(filterConfig);
            setCasServerLogoutUrl(getPropertyFromInitParams(filterConfig, "casServerLogoutUrl", null));
            logger.trace("Loaded CasServerLoginUrl parameter: {}", this.casServerLogoutUrl);
        }
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws IOException, ServletException {
        final HttpServletRequest request = (HttpServletRequest) servletRequest;
        final HttpServletResponse response = (HttpServletResponse) servletResponse;

        if ("true".equals(request.getParameter("redirected"))) {
            chain.doFilter(request, response);
            return;
        }

        String serviceUrl = constructServiceUrl(request, response);
        if (serviceUrl.contains("?")) {
            serviceUrl += "&redirected=true";
        } else {
            serviceUrl += "?redirected=true";
        }

        String redirectUrl = CommonUtils.constructRedirectUrl(this.casServerLogoutUrl, getServiceParameterName(), serviceUrl, false, false);
        response.sendRedirect(redirectUrl);
    }

    @Override
    public void destroy() {
    }

    public final void setCasServerLogoutUrl(final String casServerLogoutUrl) {
        this.casServerLogoutUrl = casServerLogoutUrl;
    }

}
