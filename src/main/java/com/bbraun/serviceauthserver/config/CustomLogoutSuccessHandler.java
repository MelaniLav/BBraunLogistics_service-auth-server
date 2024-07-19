package com.bbraun.serviceauthserver.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.io.IOException;

public class CustomLogoutSuccessHandler implements LogoutSuccessHandler {

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String redirectUrl = request.getParameter("redirectUrl");
        String isLoggedOut = request.getParameter("isLoggedOut");
        if(redirectUrl != null && !redirectUrl.isEmpty()){
            if(isLoggedOut != null & !isLoggedOut.isEmpty()) {
                redirectUrl = redirectUrl +"?param="+isLoggedOut;
            }
            response.sendRedirect(redirectUrl);
        }else {
            response.sendRedirect("http://localhost:4200/main");
        }
    }
}
