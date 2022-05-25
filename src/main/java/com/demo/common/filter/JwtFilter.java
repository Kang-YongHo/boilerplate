package com.demo.common.filter;

import com.demo.config.security.jwt.JwtProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtFilter extends OncePerRequestFilter {

    private final JwtProvider provider;

    public JwtFilter(JwtProvider provider) {
        this.provider = provider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
        FilterChain filterChain)
        throws ServletException, IOException {
        logger.info(request.getRequestURL().toString());
        try {
            String jwt = getJwtFromRequest(request);
            if (StringUtils.hasLength(jwt) && provider.validateToken(jwt)) {
//                Authentication authentication1 = provider.getAuthentication(jwt);
                UsernamePasswordAuthenticationToken authentication1 = provider.getAuthentication(
                    jwt);

                authentication1.setDetails(
                    new WebAuthenticationDetailsSource().buildDetails(request));
//                String userName = authentication1.getName();
//
//                UserAuthentication authentication = new UserAuthentication(userName, null, authentication1.getAuthorities());
//                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication1);
            } else {
                if (!StringUtils.hasText(jwt)) {
                    request.setAttribute("unauthorization", "there is no token");
                }

                if (provider.validateToken(jwt)) {
                    request.setAttribute("unauthorization", "token is expired");
                }
            }
        } catch (Exception ex) {
            logger.error("Could not set user authentication in security context", ex);
        }

        filterChain.doFilter(request, response);
    }

    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = provider.resolveToken(request);

        if (!StringUtils.hasText(bearerToken)) {
            bearerToken = request.getHeader("Authorization");
        }

        if (StringUtils.hasLength(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring("Bearer ".length());
        }
        return bearerToken;
    }
}
