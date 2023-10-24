package io.github.jokoframework.security.controller;

import io.github.jokoframework.security.ApiPaths;
import io.github.jokoframework.security.dto.AuditSessionDTO;
import io.github.jokoframework.security.dto.BaseResponseDTO;
import io.github.jokoframework.security.dto.request.AuditSessionRequestDTO;
import io.github.jokoframework.security.dto.response.AuditSessionResponseDTO;
import io.github.jokoframework.security.services.IAuditSessionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Created by afeltes on 07/09/16.
 */
@RestController
public class AuditSessionController {

    private final IAuditSessionService auditSessionService;

    public AuditSessionController(IAuditSessionService auditSessionService) {
        this.auditSessionService = auditSessionService;
    }

    @Operation(summary = "Obtiene la lista de sesiones.", description = "Obtiene la lista de sesiones ordenados por fecha de ingreso en orden descendente.")
    @ApiResponse(responseCode = "200", description = "")
    @Parameter(name = SecurityConstants.AUTH_HEADER_NAME, schema = @Schema(implementation = String.class), in = ParameterIn.HEADER, required = true, description = "User Access Token")
    @Parameter(name = SecurityConstants.VERSION_HEADER_NAME, schema = @Schema(implementation = String.class, defaultValue = "1.0"), in = ParameterIn.HEADER, required = false, description = "Version")
    @GetMapping(value = ApiPaths.SESSIONS, produces = MediaType.APPLICATION_JSON_VALUE)
    public List<AuditSessionResponseDTO> getSessions(HttpServletRequest request, HttpServletResponse response,
                                                     @Parameter(name = "startPage", description = "El número de página en que se iniciará la consulta. Si se pasa 0 no se toma en cuenta la paginación.")
                                                     @RequestParam(value = "startPage", required = false, defaultValue = "1") Integer startPage,
                                                     @Parameter(name = "rowsPerPage", description = "Cuantos resultados por página se desean consultar.")
                                                     @RequestParam(value = "rowsPerPage", required = false, defaultValue = "5") Integer rowsPerPage) {
        return auditSessionService.findAllOrderdByUserDate(startPage, rowsPerPage);
    }

    @Operation(summary = "Guarda datos relacionados a la sesión de usuario, para fines de auditoría. Para la fecha de la sesión, se toma la del servidor.")
    @ApiResponse(responseCode = "200", description = "Auditoria de sesión guardada correctamente.")
    @ApiResponse(responseCode = "409", description = "No se pudo guardar la información de auditoría.")
    @Parameter(name = SecurityConstants.AUTH_HEADER_NAME, schema = @Schema(implementation = String.class), in = ParameterIn.HEADER, required = true, description = "User Access Token")
    @Parameter(name = SecurityConstants.VERSION_HEADER_NAME, schema = @Schema(implementation = String.class, defaultValue = "1.0"), in = ParameterIn.HEADER, required = false, description = "Version")
    @PostMapping(value = ApiPaths.SESSIONS)
    public ResponseEntity<BaseResponseDTO> saveAuditSession(@RequestBody AuditSessionRequestDTO pAuditSessionRequestDTO) {
        BaseResponseDTO responseDTO = new BaseResponseDTO();
        AuditSessionDTO auditDTO = auditSessionService.save(pAuditSessionRequestDTO);
        if (auditDTO != null && auditDTO.getId() != null) {
            responseDTO.setHttpStatus(HttpStatus.OK);
            responseDTO.setSuccess(true);
        } else {
            responseDTO.setHttpStatus(HttpStatus.CONFLICT);
            responseDTO.setMessage(String.format("No se pudo guardar la información de auditoria: %s ", pAuditSessionRequestDTO));
        }
        return new ResponseEntity<>(responseDTO, responseDTO.getHttpStatus());
    }
}
