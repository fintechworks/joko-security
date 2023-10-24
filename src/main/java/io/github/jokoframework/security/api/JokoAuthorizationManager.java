package io.github.jokoframework.security.api;

import io.github.jokoframework.security.JokoJWTClaims;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * Esta clase sigue las particularidades de HttpSecurity, y solamente que ya se incluyen
 * configuraciones por default y solamente debería de enfocarse en las
 * particularidades de los URL del sitio a definir.
 */
public interface JokoAuthorizationManager {

    /**
     * Configura la seguridad y permisos por endpoint
     *
     * @see HttpSecurity#authorizeHttpRequests(Customizer)
     */
    void configure(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry http);

    /**
     * <p>
     * Si el usuario esta autenticado este metodo será ejecutado para
     * personalizar la autorizacion. Una implementacion sencilla puede ser
     * simplemente devolver el parámetro authorization
     * </p>
     * <p>
     * La lista de autorizaciones estará precargada de acuerdo a las reglas de
     * autorizaciones por defecto de Joko-security.
     * </p>
     *
     * @param claims el token
     * @param authorization La lista de autorizaciones concedidas por default a usuarios
     *                      con este tipo de tokens. Esta debería de ser la base para la
     *                      lista a retornar
     * @return la lista actualizada de autorizaciones concedidas, nunca null.
     */
    Collection<? extends GrantedAuthority> authorize(JokoJWTClaims claims,
                                                     Collection<? extends GrantedAuthority> authorization);

}
