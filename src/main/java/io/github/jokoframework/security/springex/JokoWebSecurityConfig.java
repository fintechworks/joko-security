package io.github.jokoframework.security.springex;

import ch.qos.logback.core.spi.LogbackLock;
import io.github.jokoframework.security.ApiPaths;
import io.github.jokoframework.security.api.JokoAuthorizationManager;
import io.github.jokoframework.security.controller.SecurityConstants;
import io.github.jokoframework.security.services.ITokenService;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
// TODO esto tiene que migrar a una clase separada
public class JokoWebSecurityConfig {

    private static final Logger LOGGER = LoggerFactory.getLogger(JokoWebSecurityConfig.class);
    @Autowired
    private ITokenService tokenService;

    @Autowired(required = false)
    private JokoAuthorizationManager jokoAuthorizationManager;

    @Value("${joko.authentication.enable:true}")
    private boolean authenticationEnable = true;

    /**
     * // Spring Security will never create an {@link HttpSession} and
     * // it will never use it to obtain the {@link SecurityContext}
     */
    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        if (!authenticationEnable) {
            LOGGER.warn(
                    "Authentication module is not enabled!! This configuration should only be used during development");
            http.authorizeHttpRequests(
                    auth -> auth
                            .anyRequest().anonymous()
                            .requestMatchers("/**").permitAll()
            );
            return http.build();
        }

        http.authorizeHttpRequests(auth -> {
            // Se tiene acceso al login para que cualquiera pueda intentar
            // un login
            auth.requestMatchers(ApiPaths.LOGIN).permitAll()
                    .requestMatchers(ApiPaths.LOGIN + "/").permitAll()
                    .requestMatchers(ApiPaths.TOKEN_INFO).permitAll()
                    .requestMatchers(ApiPaths.TOKEN_INFO + "/").permitAll()


                    /*
                     * Solo teniendo acceso a un refresh token se puede pedir un access
                     * token, refrescar o hacer un logout
                     */
                    // access token
                    .requestMatchers(ApiPaths.TOKEN_USER_ACCESS).hasAnyAuthority(SecurityConstants.AUTHORIZATION_REFRESH)
                    .requestMatchers(ApiPaths.TOKEN_USER_ACCESS + "/").hasAnyAuthority(SecurityConstants.AUTHORIZATION_REFRESH)
                    // refrescar
                    .requestMatchers(ApiPaths.TOKEN_REFRESH).hasAnyAuthority(SecurityConstants.AUTHORIZATION_REFRESH)
                    .requestMatchers(ApiPaths.TOKEN_REFRESH + "/").hasAnyAuthority(SecurityConstants.AUTHORIZATION_REFRESH)
                    // logout
                    .requestMatchers(ApiPaths.LOGOUT).hasAnyAuthority(SecurityConstants.AUTHORIZATION_REFRESH)
                    .requestMatchers(ApiPaths.LOGOUT + "/").hasAnyAuthority(SecurityConstants.AUTHORIZATION_REFRESH)
                    //sessions
                    .requestMatchers(ApiPaths.SESSIONS).hasAnyAuthority(SecurityConstants.AUTHORIZATION_REFRESH)
                    .requestMatchers(ApiPaths.SESSIONS + "/").hasAnyAuthority(SecurityConstants.AUTHORIZATION_REFRESH)
                    //qrcode
                    .requestMatchers("/qrcode").permitAll()


                    // Todo el resto queda por default denegado
                    .requestMatchers("/**").denyAll();

            // Configuracion de URL particular para la aplicacion
            if (jokoAuthorizationManager != null) jokoAuthorizationManager.configure(auth);
        });

        http.addFilterBefore(new JokoSecurityFilter(tokenService, jokoAuthorizationManager), UsernamePasswordAuthenticationFilter.class);

        http.exceptionHandling(eh -> eh
                .authenticationEntryPoint(new Http401UnauthorizedEntryPoint())
                .accessDeniedHandler(new JokoAccessDeniedHandler())
        );
        http.anonymous(h -> {
        });
        http.servletApi(sa -> {
        });
        http.headers(c ->
                c.cacheControl(cc -> {
                })
        );
        return http.build();
    }
}
