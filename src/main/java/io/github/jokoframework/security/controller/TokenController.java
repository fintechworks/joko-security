package io.github.jokoframework.security.controller;


import io.github.jokoframework.common.dto.JokoTokenInfoResponse;
import io.github.jokoframework.security.ApiPaths;
import io.github.jokoframework.security.JokoTokenWrapper;
import io.github.jokoframework.security.dto.JokoTokenResponse;
import io.github.jokoframework.security.services.ITokenService;
import io.github.jokoframework.security.springex.JokoSecurityContext;
import io.github.jokoframework.security.util.JokoRequestContext;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.GeneralSecurityException;

@RestController
public class TokenController {

    private final ITokenService tokenService;

    @Autowired
    public TokenController(ITokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Operation(summary = "Crea un token de acceso de usuario", description = "Dependiendo del security profile utilizado el token se creara con mayor o menor tiempo de expiración. ")
    @ApiResponse(responseCode = "202", description = "El token se ha creado exitosamente.")
    @ApiResponse(responseCode = "403", description = "En caso de proveerse un refresh token inválido")
    @Parameter(name = SecurityConstants.AUTH_HEADER_NAME, schema = @Schema(implementation = String.class, defaultValue = "Refresh token"), in = ParameterIn.HEADER, required = true)
    @PostMapping(value = ApiPaths.TOKEN_USER_ACCESS, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<JokoTokenResponse> createTokenUserAccess(@RequestHeader(value = "SEED_OTP_TOKEN", required = false) String otp) throws GeneralSecurityException {


        JokoTokenWrapper accessTokenWrapper = tokenService.createAccessToken(JokoSecurityContext.getClaims(), otp);
        return new ResponseEntity<>(new JokoTokenResponse(accessTokenWrapper), HttpStatus.OK);

    }

    @Operation(summary = "Refresca un token, y vuelve a setear su tiempo de duración",
            description = "El token viene en la variable "
                    + SecurityConstants.AUTH_HEADER_NAME + " de la  cabecera. "
                    + "Si el token es válido y no ha sido revocado se puede refrescar")
    @ApiResponse(responseCode = "202", description = "El token se ha renovado exitosamente.")
    @ApiResponse(responseCode = "409", description = "En caso de proveerse un parámetro inválido")
    @Parameter(name = SecurityConstants.AUTH_HEADER_NAME, schema = @Schema(implementation = String.class, defaultValue = "Refresh token"), in = ParameterIn.HEADER, required = true)
    @PostMapping(value = ApiPaths.TOKEN_REFRESH, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<JokoTokenResponse> refreshToken(HttpServletRequest httpRequest) {

        JokoRequestContext jokoRequest = new JokoRequestContext(httpRequest);

        JokoTokenWrapper refreshedToken = tokenService.refreshToken(JokoSecurityContext.getClaims(),
                jokoRequest.getUserAgent(), httpRequest.getRemoteAddr());

        return new ResponseEntity<>(new JokoTokenResponse(refreshedToken), HttpStatus.OK);

    }

    @RequestMapping(value = ApiPaths.TOKEN_INFO, method = RequestMethod.GET)
    public ResponseEntity<JokoTokenInfoResponse> tokenInfo(@RequestParam("accessToken") String accessToken) {
        JokoTokenInfoResponse response = tokenService.tokenInfo(accessToken);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }
}
