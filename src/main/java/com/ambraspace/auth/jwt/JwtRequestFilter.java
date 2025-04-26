package com.ambraspace.auth.jwt;

import java.io.IOException;
import java.time.Duration;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;


/* https://www.javainuse.com/webseries/spring-security-jwt/chap7 */
@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    @Autowired
    private UserDetailsService userService;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private JwtTokenUtil2FA jwtTokenUtil2FA;

    @Value("${jwt.verify-url:/verify}")
    private String verifyURL;

    @Value("${jwt.refresh-url:/refreshtoken}")
    private String refreshURL;

    @Value("${jwt.refresh-token-validity:#{T(java.time.Duration).ofHours(2)}}")
    private Duration refreshTokenValidity;


    private final Logger logger = LoggerFactory.getLogger(JwtRequestFilter.class);


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        // JWT Token is in the form "Bearer token". Remove Bearer word and
        // get only the Token
        String jwtToken = jwtTokenUtil.extractJwtFromRequest(request);

        if (StringUtils.hasText(jwtToken))
        {

            if (request.getRequestURI().equals(verifyURL))
            {

                try {

                    if (jwtTokenUtil2FA.validateToken(jwtToken))
                    {
                        UserDetails userDetails =
                                userService.loadUserByUsername(jwtTokenUtil2FA.getUsernameFromToken(jwtToken));

                        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                                new UsernamePasswordAuthenticationToken(
                                        userDetails, null, userDetails.getAuthorities());
                        // After setting the Authentication in the context, we specify
                        // that the current user is authenticated. So it passes the
                        // Spring Security Configurations successfully.
                        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                    } else {
                        logger.warn("Cannot set the Security Context");
                    }

                } catch (ExpiredJwtException ex) {
                    request.setAttribute("exception", ex);
                } catch (BadCredentialsException ex) {
                    request.setAttribute("exception", ex);
                } catch (Exception ex) {
                	logger.error(ex.getMessage());
                }

            } else {

                try {

                    if (jwtTokenUtil.validateToken(jwtToken))
                    {
                        UserDetails userDetails =
                                userService.loadUserByUsername(jwtTokenUtil.getUsernameFromToken(jwtToken));

                        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                                new UsernamePasswordAuthenticationToken(
                                        userDetails, null, userDetails.getAuthorities());
                        // After setting the Authentication in the context, we specify
                        // that the current user is authenticated. So it passes the
                        // Spring Security Configurations successfully.
                        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                    } else {
                    	logger.warn("Cannot set the Security Context");
                    }

                } catch (ExpiredJwtException ex) {

                    String requestURL = request.getRequestURI();
                    Date expiration = ex.getClaims().getExpiration();
                    // allow for Refresh Token creation if following conditions are true.
                    if (requestURL.equals(refreshURL) &&
                            expiration.after(
                                    new Date(System.currentTimeMillis() - refreshTokenValidity.toMillis())))
                    {
                        allowForRefreshToken(ex, request);
                    } else {
                        request.setAttribute("exception", ex);
                    }
                } catch (BadCredentialsException ex) {
                    request.setAttribute("exception", ex);
                } catch (Exception ex) {
                    logger.error(ex.getMessage());
                }

            }

        }

        chain.doFilter(request, response);
    }


    private void allowForRefreshToken(ExpiredJwtException ex, HttpServletRequest request) {

        // create a UsernamePasswordAuthenticationToken with null values.
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                null, null, null);
        // After setting the Authentication in the context, we specify
        // that the current user is authenticated. So it passes the
        // Spring Security Configurations successfully.
        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);

    }


}