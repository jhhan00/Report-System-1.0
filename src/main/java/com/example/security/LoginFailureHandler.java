package com.example.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Enumeration;

@Configuration
public class LoginFailureHandler implements AuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
            throws IOException, ServletException {

        String errormsg = "";
        String userID = request.getParameter("username");
        String userPW = request.getParameter("password");

        Enumeration<String> keys = request.getParameterNames();
        while(keys.hasMoreElements()) {
            String key = keys.nextElement();
            System.out.println(key + "_:_" + request.getParameter(key));
        }

        if(exception instanceof UsernameNotFoundException) {
            errormsg = "Sign Up!";
        } else if(exception instanceof BadCredentialsException) {
            errormsg = "Wrong Id or PW";
        } else if(exception instanceof DisabledException) {
            errormsg = "Not Activated account";
        } else {
            errormsg = "Error";
        }
        System.out.println(errormsg);

        request.setAttribute("errormessage", errormsg);

//        response.sendRedirect("/login?error");
        request.getRequestDispatcher("/login?error").forward(request, response);
    }
}
