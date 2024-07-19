package com.bbraun.serviceauthserver.controllers;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class LoginController {


    @GetMapping("/login")
    public String login(){
        return "login";
    }




    @GetMapping("/logout")
    public String logout(){
        return "logout";
    }



    @PostMapping("/logout")
    public String logoutOK(HttpSecurity http) throws Exception {
        http.logout(logout -> logout
                .deleteCookies("JSESSIONID")
                .invalidateHttpSession(true)
                .clearAuthentication(true));

        return "login?logout";
    }
}
