package io.github.jokoframework.security.springex;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.jokoframework.common.dto.JokoBaseResponse;
import io.github.jokoframework.security.errors.JokoUnauthenticatedException;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
import java.io.PrintWriter;

public class Http401UnauthorizedEntryPoint implements AuthenticationEntryPoint {

    private final Logger log = LoggerFactory.getLogger(Http401UnauthorizedEntryPoint.class);

    /**
     * Always returns a 401 error code to the client.
     */
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException arg2)
            throws IOException, ServletException {

        log.debug("Pre-authenticated entry point called. Rejecting access to " + request.getRequestURI());

        JokoBaseResponse error = new JokoBaseResponse();
        error.setSuccess(false);
        error.setErrorCode(JokoUnauthenticatedException.ERROR_CODE_WRONG_CREDENTIALS);
        error.setMessage("You shall not pass!!");

        ObjectMapper mapper = new ObjectMapper();

        response.setHeader("Content-type", "application/json");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        PrintWriter out = response.getWriter();
        mapper.writeValue(out, error);

    }
}
