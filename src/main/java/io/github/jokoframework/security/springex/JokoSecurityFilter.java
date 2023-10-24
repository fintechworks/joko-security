package io.github.jokoframework.security.springex;

import io.github.jokoframework.common.JokoUtils;
import io.github.jokoframework.security.JokoJWTClaims;
import io.github.jokoframework.security.api.JokoAuthorizationManager;
import io.github.jokoframework.security.controller.SecurityConstants;
import io.github.jokoframework.security.services.ITokenService;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;
import java.util.Collection;

/**
 * Comprueba los requests hechos en busca del token de autenticación. El token
 * de autenticación se encuentra siempre en
 * {@value SecurityConstants#AUTH_HEADER_NAME}.
 *
 * Si se encuentra un token se llamara al autoriza
 *
 * @author danicricco
 *
 */
public class JokoSecurityFilter extends GenericFilterBean {

    private static final Logger JOKO_LOGGER = LoggerFactory.getLogger(JokoSecurityFilter.class);
    private ITokenService tokenService;

    private JokoAuthorizationManager jokoAuthorizationManager;

    public JokoSecurityFilter(ITokenService tokenService, JokoAuthorizationManager jokoAuthorizationManager) {
        this.tokenService = tokenService;
        this.jokoAuthorizationManager = jokoAuthorizationManager;
    }

    public static String getTokenFromHeader(HttpServletRequest pRequest) {
        String token = pRequest.getHeader(SecurityConstants.AUTH_HEADER_NAME);
        return token;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
            throws IOException, ServletException {
        JokoJWTClaims claims = validateToken(request);
        if (claims != null) {

            Collection<? extends GrantedAuthority> baseAuthorizations = JokoSecurityContext.determineAuthorizations(claims);
            Collection<? extends GrantedAuthority> authorities = jokoAuthorizationManager.authorize(
            		claims,
                    baseAuthorizations);

            JokoAuthenticated authentication = new JokoAuthenticated(claims, authorities);
            JokoSecurityContext.setAuthentication(authentication);

            if (JOKO_LOGGER.isDebugEnabled()) {

                HttpServletRequest httpRequest = (HttpServletRequest) request;
                String uri = httpRequest.getRequestURI();

                JOKO_LOGGER.debug("Authorized user " + JokoUtils.formatLogString(claims.getSubject()) + " to: "
                        + JokoUtils.join(authorities, ",") + " Request-URI " + uri + " jti " + claims.getId());
            }

        } else {
            JokoSecurityContext.clearContext();
        }
        filterChain.doFilter(request, response);
        JokoSecurityContext.clearContext();

    }

    /**
     * Si el token es valido retorna un {@link JokoJWTClaims}. Si el token NO es
     * valido retorna null
     *
     * @param request
     * @return
     */
    private JokoJWTClaims validateToken(ServletRequest request) {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String token = getTokenFromHeader(httpRequest);
        if (token == null) {
            return null;
        }

        try {
        	return tokenService.tokenInfoAsClaims(token).orElse(null);
        } catch (JwtException | IllegalArgumentException e) {

            String uri = httpRequest.getRequestURI();
            String userAgent = httpRequest.getHeader("User-Agent");
            JOKO_LOGGER.debug(uri + " from User-Agent: " + userAgent + " Unable to authenticate " + e.getClass() + ": "
                    + e.getMessage());
            JOKO_LOGGER.debug("Token received: " + token);
            JOKO_LOGGER.trace("Error validando el token.", e);
            return null;
        }
    }

	
}
