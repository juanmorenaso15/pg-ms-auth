package com.pulse_gym.ms_auth.controller;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.pulse_gym.lb_common.dto.MessegeGlobalDTO;
import com.pulse_gym.lb_common.dto.RestablecerContrasena;
import com.pulse_gym.lb_common.dto.SolicitudTokenBiometricoDTO;
import com.pulse_gym.lb_common.entity.auth.User;
import com.pulse_gym.lb_common.services.JwtService;
import com.pulse_gym.lb_common.dto.AuthUserDTO;
import com.pulse_gym.lb_common.dto.BiometricLoginRequestDTO;
import com.pulse_gym.lb_common.dto.ChangePasswordRequestDTO;
import com.pulse_gym.lb_common.dto.ContrasenaOlvidada;
import com.pulse_gym.lb_common.dto.HttpGlobalResponse;
import com.pulse_gym.lb_common.dto.JwtDTO;
import com.pulse_gym.ms_auth.dto.LoginRequestDTO;
import com.pulse_gym.ms_auth.dto.RegisterRequestDTO;
import com.pulse_gym.ms_auth.repository.UserAuthRepository;
import com.pulse_gym.ms_auth.services.AuthService;
import com.pulse_gym.ms_auth.services.BiometricTokenService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;
    private final UserAuthRepository userAuthRepository;
    private final BiometricTokenService biometricTokenService;
    private final JwtService jwtService;

    /**
     * Registro de usuario
     */
    @PostMapping("/register")
    public ResponseEntity<MessegeGlobalDTO> register(@Valid @RequestBody RegisterRequestDTO requestDTO) {
        try {
            MessegeGlobalDTO messegeGlobalDTO = authService.register(requestDTO);
            return ResponseEntity.status(HttpStatus.ACCEPTED).body(messegeGlobalDTO);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
        }
    }

    /**
     * Inicio de sesion del usuario
     */
    @PostMapping("/login")
    public ResponseEntity<HttpGlobalResponse<JwtDTO>> login(@RequestBody LoginRequestDTO request) {
        try {
            HttpGlobalResponse<JwtDTO> response = authService.login(request);
            return ResponseEntity.status(HttpStatus.ACCEPTED).body(response);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
        }
    }

    /**
     * Refresco del jwt
     */
    @GetMapping("/refresh")
    public ResponseEntity<JwtDTO> refreshToken(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
        }

        String token = authHeader.replaceFirst("Bearer ", "");
        JwtDTO response = new JwtDTO();

        try {
            response = authService.refreshToken(token);
            return ResponseEntity.status(HttpStatus.ACCEPTED).body(response);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
        }
    }

    /**
     * Endpoint para solicitar recuperación de contraseña
     */
    @PostMapping("/forgot-password")
    public ResponseEntity<MessegeGlobalDTO> forgotPassword(@Valid @RequestBody ContrasenaOlvidada requestDTO) {
        try {
            MessegeGlobalDTO response = authService.forgotPassword(requestDTO);
            return ResponseEntity.status(HttpStatus.OK).body(response);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new MessegeGlobalDTO("Error al procesar la solicitud"));
        }
    }

    /**
     * Endpoint para restablecer la contraseña con token
     */
    @PostMapping("/reset-password")
    public ResponseEntity<MessegeGlobalDTO> resetPassword(@Valid @RequestBody RestablecerContrasena requestDTO) {
        try {
            MessegeGlobalDTO response = authService.resetPassword(requestDTO);
            HttpStatus status = response.getMessage().contains("exitosamente") ? HttpStatus.OK : HttpStatus.BAD_REQUEST;
            return ResponseEntity.status(status).body(response);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new MessegeGlobalDTO("Error al restablecer la contraseña"));
        }
    }

    /**
     * Endpoint interno para obtener usuario por email (usado por otros
     * microservicios)
     */
    @GetMapping("/api/internal/users/email/{email}")
    public ResponseEntity<AuthUserDTO> getUserByEmail(@PathVariable String email) {
        User user = userAuthRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        AuthUserDTO dto = new AuthUserDTO();
        dto.setId(user.getId());
        dto.setEmail(user.getEmail());
        dto.setUsername(user.getUsername());
        dto.setRol(user.getRol());
        dto.setEstado(user.getEstado());
        return ResponseEntity.ok(dto);
    }

    /**
     * Endpoint interno para obtener usuario por ID (usado por otros microservicios)
     */
    @GetMapping("/api/internal/users/{id}")
    public ResponseEntity<AuthUserDTO> getUserById(@PathVariable Long id) {
        User user = userAuthRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado con id: " + id));

        AuthUserDTO dto = new AuthUserDTO();
        dto.setId(user.getId());
        dto.setEmail(user.getEmail());
        dto.setUsername(user.getUsername());
        dto.setRol(user.getRol());
        dto.setEstado(user.getEstado());
        return ResponseEntity.ok(dto);
    }

    /**
     * Genera un token biométrico JWT para un socio.
     * Valida que el usuario exista y tenga rol SOCIO.
     * 
     * @param request DTO con userId y deviceId
     * @return Token JWT biométrico firmado
     */
    @PostMapping("/biometric/token")
    public ResponseEntity<JwtDTO> generateBiometricToken(@Valid @RequestBody SolicitudTokenBiometricoDTO request) {
        try {
            // Verificar que el usuario existe
            User user = userAuthRepository.findById(request.getUserId())
                    .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

            // Verificar que sea socio
            if (user.getRol() == null || !user.getRol().name().equalsIgnoreCase("socio")) {
                throw new RuntimeException("Solo los socios pueden generar tokens biométricos");
            }

            // Generar token
            String token = biometricTokenService.generateToken(request.getUserId(), request.getDeviceId());

            JwtDTO response = new JwtDTO();
            response.setJwt(token);
            return ResponseEntity.status(HttpStatus.OK).body(response);

        } catch (RuntimeException e) {
            // Devolver error 400 con mensaje claro
            JwtDTO errorDto = new JwtDTO();
            errorDto.setJwt(e.getMessage());
            return new ResponseEntity<JwtDTO>(errorDto, HttpStatus.BAD_REQUEST);
        } catch (Exception e) {
            e.printStackTrace();
            JwtDTO errorDto = new JwtDTO();
            errorDto.setJwt("Error interno al generar el token");
            return new ResponseEntity<JwtDTO>(errorDto, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Autenticación biométrica (login con huella)
     * POST /auth/biometric/login
     * 
     * @param tokenRequest DTO con el token biométrico
     * @return Token JWT de acceso normal (para la aplicación)
     */
    @PostMapping("/biometric/login")
    public ResponseEntity<HttpGlobalResponse<JwtDTO>> loginBiometrico(
            @RequestBody BiometricLoginRequestDTO tokenRequest) {
        try {
            HttpGlobalResponse<JwtDTO> response = authService.loginBiometrico(tokenRequest.getToken());
            HttpStatus status = response.getMessage().contains("exitosa")
                    ? HttpStatus.OK
                    : HttpStatus.UNAUTHORIZED;
            return ResponseEntity.status(status).body(response);
        } catch (Exception e) {
            e.printStackTrace();
            HttpGlobalResponse<JwtDTO> errorResponse = new HttpGlobalResponse<>();
            errorResponse.setMessage("Error interno al procesar la autenticación biométrica");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Cambio de contraseña de usuario autenticado
     * POST /auth/change-password
     * 
     * @param requestDTO DTO con contraseña actual, nueva y confirmación
     * @param authHeader Header Authorization con el token JWT
     * @return Mensaje de éxito o error
     */
    @PostMapping("/change-password")
    public ResponseEntity<MessegeGlobalDTO> changePassword(
            @Valid @RequestBody ChangePasswordRequestDTO requestDTO,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        try {
            // 1. Extraer userId del token
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new MessegeGlobalDTO("Token no proporcionado"));
            }

            String token = authHeader.substring(7);
            Long userId = jwtService.extractUserId(token);

            if (userId == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new MessegeGlobalDTO("Token inválido"));
            }

            // 2. Llamar al servicio
            MessegeGlobalDTO response = authService.changePassword(userId, requestDTO);
            return ResponseEntity.ok(response);

        } catch (RuntimeException e) {
            // Devolver error con mensaje claro
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new MessegeGlobalDTO(e.getMessage()));
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new MessegeGlobalDTO("Error al cambiar la contraseña"));
        }
    }

    @GetMapping("/usuarios")
    public ResponseEntity<List<AuthUserDTO>> obtenerTodosLosUsuarios(
            @RequestHeader(value = "X-User-Rol", required = false) String rol) {
        try {
            List<AuthUserDTO> usuarios = authService.obtenerUsuarios(rol);
            return ResponseEntity.status(HttpStatus.OK).body(usuarios);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }

    @PutMapping("/usuarios/estado/{id}")
    public ResponseEntity<MessegeGlobalDTO> cambiarEstadoUsuario(
            @PathVariable Long id,
            @RequestHeader(value = "X-User-Rol", required = false) String rol) {
        try {
            MessegeGlobalDTO response = authService.cambiarEstadoUsuario(id, rol);
            return ResponseEntity.status(HttpStatus.OK).body(response);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new MessegeGlobalDTO(e.getMessage()));
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new MessegeGlobalDTO("Error al cambiar el estado del usuario"));
        }
    }
    
}