package com.pulse_gym.ms_auth.services;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.pulse_gym.lb_common.client.AuthServiceClient;
import com.pulse_gym.lb_common.client.NotificacionClient;
import com.pulse_gym.lb_common.client.UsuarioClient;
import com.pulse_gym.lb_common.dto.AuthUserDTO;
import com.pulse_gym.lb_common.dto.ChangePasswordRequestDTO;
import com.pulse_gym.lb_common.dto.ContrasenaOlvidada;
import com.pulse_gym.lb_common.dto.EnvioEventoNotificacionDTO;
import com.pulse_gym.lb_common.dto.HttpGlobalResponse;
import com.pulse_gym.lb_common.dto.JwtDTO;
import com.pulse_gym.lb_common.dto.MessegeGlobalDTO;
import com.pulse_gym.lb_common.dto.RespuestaPaginadaDTO;
import com.pulse_gym.lb_common.dto.RestablecerContrasena;
import com.pulse_gym.lb_common.dto.UsuarioPerfilResponseDTO;
import com.pulse_gym.lb_common.entity.auth.PasswordResetToken;
import com.pulse_gym.lb_common.entity.auth.User;
import com.pulse_gym.lb_common.enums.EnumEventoAsociado;
import com.pulse_gym.lb_common.services.BiometricJwtService;
import com.pulse_gym.lb_common.services.JwtService;
import com.pulse_gym.lb_common.services.ValidacionDeRoles;
import com.pulse_gym.ms_auth.dto.LoginRequestDTO;
import com.pulse_gym.ms_auth.dto.RegisterRequestDTO;
import com.pulse_gym.ms_auth.repository.PasswordResetTokenRepository;
import com.pulse_gym.ms_auth.repository.UserAuthRepository;
import com.pulse_gym.ms_auth.specifications.EspecificacionesUsuario;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    /** Repositorio para operaciones CRUD de usuarios de autenticación */
    private final UserAuthRepository userAuthRepository;

    /** Codificador de contraseñas usando BCrypt */
    private final PasswordEncoder passwordEncoder;

    /** Servicio para generación y validación de tokens JWT */
    private final JwtService jwtService;

    /** Servicio para envío de correos electrónicos */
    private final EmailService emailService;

    /** Repositorio para tokens de restablecimiento de contraseña */
    private final PasswordResetTokenRepository tokenRepository;

    /** Cliente Feign para comunicación con el microservicio de notificaciones */
    private final NotificacionClient notificacionClient;

    /** Servicio para generación y validación de tokens biométricos */
    private final BiometricJwtService biometricJwtService;

    /**
     * Cliente para interactuar con el microservicio de usuarios (pg-ms-users)
     */
    private final UsuarioClient usuarioClient;

    @Autowired
    private CacheManager cacheManager;

    /** Valores constantes para la gestión de intentos fallidos */
    private static final int MAX_ATTEMPTS = 3;

    /** Duración del bloqueo en segundos */
    private static final int LOCK_DURATION_SECONDS = 30;

    /** Tiempo de expiración del token de restablecimiento en minutos */
    @Value("${app.security.reset-token-expiration-minutes:10}")
    private long tokenExpirationMinutes;

    /**
     * Genera un código OTP de 4 dígitos para restablecimiento de contraseña.
     *
     * @return Código OTP de 4 dígitos como String
     */
    private String generateOTP() {
        int otp = 1000 + (int) (Math.random() * 9000);
        return String.valueOf(otp);
    }

    /**
     * Registra un nuevo usuario en el sistema.
     * Valida que el email no esté en uso, crea el usuario y envía notificación de
     * registro.
     *
     * @param requestDTO Datos del usuario a registrar (email, password, username,
     *                   rol, estado)
     * @return Mensaje de éxito si se registró correctamente, o error si el email ya
     *         existe
     */
    public MessegeGlobalDTO register(RegisterRequestDTO requestDTO) {
        List<Object[]> duplicates = userAuthRepository.checkDuplicates(requestDTO.getEmail(), requestDTO.getUsername()).orElse(List.of());

        if (!duplicates.isEmpty()) {
            for (Object[] data : duplicates) {
                String email = (String) data[0];
                String username = (String) data[1];
                if (email != null && email.equals(requestDTO.getEmail())) {
                    return new MessegeGlobalDTO("El correo ya está en uso");
                }
                if (username != null && username.equals(requestDTO.getUsername())) {
                    return new MessegeGlobalDTO("El nombre de usuario ya está en uso");
                }
            }
        }

        User user = new User();
        user.setEmail(requestDTO.getEmail());
        user.setPassword(passwordEncoder.encode(requestDTO.getPassword()));
        user.setUsername(requestDTO.getUsername());
        user.setRol(requestDTO.getRol());
        user.setEstado(requestDTO.getEstado());
        user.setFechaRegistro(LocalDateTime.now());

        userAuthRepository.save(user);

        if (notificacionClient != null) {
            enviarNotificacionRegistroAsync(user);
        }

        return new MessegeGlobalDTO("Se ha registrado correctamente");
    }

    /**
     * Envía una notificación de registro de usuario de manera asíncrona.
     * 
     * @param user Usuario recién registrado
     */
    @Async
    public void enviarNotificacionRegistroAsync(User user) {
        try {
            EnvioEventoNotificacionDTO eventoDTO = new EnvioEventoNotificacionDTO();
            eventoDTO.setUsuarioId(user.getId());
            eventoDTO.setEvento(EnumEventoAsociado.REGISTRO_USUARIO);
            eventoDTO.setVariablesAdicionales(Map.of(
                    "username", user.getUsername(),
                    "email", user.getEmail(),
                    "nombre", user.getUsername(),
                    "fecha_registro", LocalDateTime.now().toString()));
            notificacionClient.enviarPorEvento(eventoDTO);
        } catch (Exception e) {
            log.error("Error enviando notificación de registro: {}", e.getMessage());
        }
    }

    /**
     * Inicia sesión de un usuario existente.
     * Valida credenciales y genera token JWT.
     *
     * @param requestDTO Credenciales de login (email, password)
     * @return Respuesta con token JWT y mensaje de éxito o error
     */
    @Transactional
    public HttpGlobalResponse<JwtDTO> login(LoginRequestDTO requestDTO) {
        HttpGlobalResponse<JwtDTO> response = new HttpGlobalResponse<>();

        Optional<User> userOpt = findUserByEmail(requestDTO.getEmail());
        if (userOpt.isEmpty()) {
            response.setMessage("Este usuario no se encuentra registrado");
            return response;
        }

        User user = userOpt.get();

        if (!Boolean.TRUE.equals(user.getEstado())) {
            response.setMessage("Usuario inactivo. Contacte con administración.");
            return response;
        }

        if (user.isLocked()) {
            long secondsRemaining = Duration.between(
                    LocalDateTime.now(),
                    user.getLockTime().plusSeconds(LOCK_DURATION_SECONDS)).getSeconds();
            response.setMessage(
                    "Demasiados intentos fallidos. Cuenta bloqueada por " + secondsRemaining + " segundos.");
            return response;
        }

        if (!passwordEncoder.matches(requestDTO.getPassword(), user.getPassword())) {
            user.incrementFailedAttempts();
            userAuthRepository.save(user);
            cacheManager.getCache("users").evict(requestDTO.getEmail());

            int remainingAttempts = MAX_ATTEMPTS - (user.getFailedAttempts() == null ? 0 : user.getFailedAttempts());
            if (remainingAttempts <= 0) {
                response.setMessage(
                        "Demasiados intentos fallidos. Cuenta bloqueada por " + LOCK_DURATION_SECONDS + " segundos.");
            } else {
                response.setMessage("Credenciales incorrectas. Te quedan " + remainingAttempts + " intentos.");
            }
            return response;
        }

        user.resetFailedAttempts();
        userAuthRepository.save(user);
        cacheManager.getCache("users").evict(requestDTO.getEmail());

        JwtDTO jwtDTO = new JwtDTO();
        String jwt = jwtService.generateToken(user.getId(), user.getRol().name(), user.getEmail());
        jwtDTO.setJwt(jwt);
        response.setMessage("Inicio de sesión exitoso");
        response.setData(jwtDTO);

        if (notificacionClient != null) {
            enviarNotificacionLoginAsync(user);
        }

        return response;
    }

    /**
     * Refresca un token JWT que está cerca de expirar.
     *
     * @param token Token JWT actual
     * @return Nuevo token JWT renovado
     * @throws Exception Si el token es inválido o está expirado
     */
    public JwtDTO refreshToken(String token) throws Exception {
        JwtDTO responseDTO = new JwtDTO();
        String jwt = jwtService.refreshToken(token);
        responseDTO.setJwt(jwt);
        return responseDTO;
    }

    /**
     * Solicita recuperación de contraseña enviando un código OTP al email del
     * usuario.
     *
     * @param requestDTO Contiene el username del usuario
     * @return Mensaje de éxito o error
     */
    @Transactional
    public MessegeGlobalDTO forgotPassword(ContrasenaOlvidada requestDTO) {
        Optional<User> userOpt = userAuthRepository.findByUsername(requestDTO.getUsername());

        if (userOpt.isEmpty()) {
            return new MessegeGlobalDTO("Si el username existe, recibirás un email con instrucciones");
        }

        User user = userOpt.get();

        tokenRepository.deleteByUserId(user.getId());

        String token = generateOTP();

        PasswordResetToken resetToken = new PasswordResetToken();
        resetToken.setToken(token);
        resetToken.setUser(user);
        resetToken.setExpiryDate(LocalDateTime.now().plusMinutes(tokenExpirationMinutes));
        resetToken.setUsed(false);

        tokenRepository.save(resetToken);

        emailService.sendPasswordResetEmailSimple(user.getEmail(), user.getUsername(), token);

        return new MessegeGlobalDTO("Si el username existe, recibirás un email con instrucciones");
    }

    /**
     * Restablece la contraseña usando un token OTP válido.
     *
     * @param requestDTO Contiene token, nueva contraseña y confirmación
     * @return Mensaje de éxito o error
     */
    @Transactional
    public MessegeGlobalDTO resetPassword(RestablecerContrasena requestDTO) {
        if (!requestDTO.getNewPassword().equals(requestDTO.getConfirmPassword())) {
            return new MessegeGlobalDTO("Las contraseñas no coinciden");
        }

        Optional<PasswordResetToken> tokenOpt = tokenRepository.findByToken(requestDTO.getToken());

        if (tokenOpt.isEmpty()) {
            return new MessegeGlobalDTO("Token inválido o expirado");
        }

        PasswordResetToken resetToken = tokenOpt.get();

        if (resetToken.isUsed()) {
            return new MessegeGlobalDTO("Este token ya ha sido utilizado");
        }

        if (resetToken.isExpired()) {
            return new MessegeGlobalDTO("El token ha expirado");
        }

        User user = resetToken.getUser();

        user.setPassword(passwordEncoder.encode(requestDTO.getNewPassword()));
        userAuthRepository.save(user);

        resetToken.setUsed(true);
        tokenRepository.save(resetToken);

        return new MessegeGlobalDTO("Contraseña restablecida exitosamente");
    }

    /**
     * Autenticación biométrica usando el token JWT biométrico.
     * 
     * @param biometricToken Token JWT generado por el dispositivo biométrico
     * @return Token JWT de acceso normal (para la aplicación)
     * @throws RuntimeException Si la autenticación falla
     */
    @Transactional
    public HttpGlobalResponse<JwtDTO> loginBiometrico(String biometricToken) {
        HttpGlobalResponse<JwtDTO> response = new HttpGlobalResponse<>();

        if (!biometricJwtService.validateToken(biometricToken)) {
            response.setMessage("Huella no reconocida. Intente de nuevo o use otro método.");
            return response;
        }

        if (biometricJwtService.isTokenExpired(biometricToken)) {
            response.setMessage("Huella no reconocida. Intente de nuevo o use otro método.");
            return response;
        }

        Long userId = biometricJwtService.extractUserId(biometricToken);
        String deviceId = biometricJwtService.extractDeviceId(biometricToken);

        if (userId == null || deviceId == null) {
            response.setMessage("Huella no reconocida. Intente de nuevo o use otro método.");
            return response;
        }

        UsuarioPerfilResponseDTO usuarioPerfil;
        try {
            usuarioPerfil = usuarioClient.obtenerUsuarioPorIdInterno(userId);
        } catch (Exception e) {
            response.setMessage("Error interno al validar la huella");
            return response;
        }

        if (usuarioPerfil == null) {
            response.setMessage("Huella no reconocida. Intente de nuevo o use otro método.");
            return response;
        }

        if (usuarioPerfil.getEstado() == null ||
                !usuarioPerfil.getEstado().name().equalsIgnoreCase("ACTIVO")) {
            response.setMessage("Usuario inactivo. Contacte con administración.");
            return response;
        }

        String hashGuardado = usuarioPerfil.getBiometricDeviceId();
        if (hashGuardado == null || hashGuardado.trim().isEmpty()) {
            response.setMessage("Huella no reconocida. Intente de nuevo o use otro método.");
            return response;
        }

        String hashDeviceIdToken = biometricJwtService.generateHash(deviceId);
        if (hashDeviceIdToken == null || !hashDeviceIdToken.equals(hashGuardado)) {
            response.setMessage("Huella no reconocida. Intente de nuevo o use otro método.");
            return response;
        }

        User authUser = userAuthRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Usuario de autenticación no encontrado"));

        String jwt = jwtService.generateToken(authUser.getId(), authUser.getRol().name(), authUser.getEmail());

        JwtDTO jwtDTO = new JwtDTO();
        jwtDTO.setJwt(jwt);
        response.setMessage("Autenticación biométrica exitosa");
        response.setData(jwtDTO);

        return response;
    }

    /**
     * Cambia la contraseña de un usuario autenticado.
     * Valida la contraseña actual, aplica políticas de seguridad,
     * encripta la nueva y actualiza la base de datos.
     * 
     * @param userId     ID del usuario autenticado
     * @param requestDTO DTO con contraseña actual, nueva y confirmación
     * @return Mensaje de éxito
     * @throws RuntimeException si alguna validación falla
     */
    @Transactional
    public MessegeGlobalDTO changePassword(Long userId, ChangePasswordRequestDTO requestDTO) {
        // 1. Buscar usuario
        User user = userAuthRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        // 2. Validar contraseña actual
        if (!passwordEncoder.matches(requestDTO.getCurrentPassword(), user.getPassword())) {
            throw new RuntimeException("La contraseña actual es incorrecta");
        }

        // 3. Validar que nueva contraseña coincida con confirmación
        if (!requestDTO.getNewPassword().equals(requestDTO.getConfirmPassword())) {
            throw new RuntimeException("La nueva contraseña y la confirmación no coinciden");
        }

        // 4. Validar que la nueva contraseña no sea igual a la actual
        if (passwordEncoder.matches(requestDTO.getNewPassword(), user.getPassword())) {
            throw new RuntimeException("La nueva contraseña no puede ser igual a la actual");
        }

        // 5. Encriptar nueva contraseña con BCrypt
        String encodedPassword = passwordEncoder.encode(requestDTO.getNewPassword());

        // 6. Actualizar en BD
        user.setPassword(encodedPassword);
        userAuthRepository.save(user);

        return new MessegeGlobalDTO("Contraseña actualizada exitosamente");
    }

    /**
     * Obtiene usuarios con paginación y filtros opcionales.
     * 
     * @param rolHeader rol del usuario que hace la petición (para validar admin)
     * @param activo    filtro por estado (true=activo, false=inactivo, null=sin
     *                  filtro)
     * @param rol       filtro por rol (nombre del rol, null=sin filtro)
     * @param pageable  objeto de paginación
     * @return respuesta paginada con AuthUserDTO
     */
    public RespuestaPaginadaDTO<AuthUserDTO> obtenerUsuariosConFiltros(String rolHeader, Boolean activo, String rol,
            Pageable pageable) {
        ValidacionDeRoles.validarAdmin(rolHeader);

        Specification<User> especificacion = Specification.where(null);
        if (activo != null) {
            especificacion = especificacion.and(EspecificacionesUsuario.tieneEstado(activo));
        }
        if (rol != null && !rol.isBlank()) {
            especificacion = especificacion.and(EspecificacionesUsuario.tieneRol(rol));
        }

        Page<User> paginaUsuarios = userAuthRepository.findAll(especificacion, pageable);

        List<AuthUserDTO> contenido = paginaUsuarios.getContent().stream()
                .map(this::convertirADTO)
                .collect(Collectors.toList());

        return new RespuestaPaginadaDTO<>(
                contenido,
                paginaUsuarios.getNumber(),
                paginaUsuarios.getSize(),
                paginaUsuarios.getTotalElements(),
                paginaUsuarios.getTotalPages(),
                paginaUsuarios.isLast());
    }

    /**
     * Convierte un objeto User a AuthUserDTO.
     * 
     * @param user objeto User
     * @return objeto AuthUserDTO
     */
    private AuthUserDTO convertirADTO(User user) {
        AuthUserDTO dto = new AuthUserDTO();
        dto.setId(user.getId());
        dto.setEmail(user.getEmail());
        dto.setUsername(user.getUsername());
        dto.setRol(user.getRol());
        dto.setEstado(user.getEstado());
        return dto;
    }

    /**
     * Cambia el estado de un usuario (activo/inactivo).
     * Valida que el usuario que hace la petición sea admin.
     * 
     * @param id  ID del usuario a cambiar
     * @param rol rol del usuario que hace la petición (para validar admin)
     * @return mensaje de éxito
     */
    public MessegeGlobalDTO cambiarEstadoUsuario(Long id, String rol) {
        ValidacionDeRoles.validarAdmin(rol);

        User user = userAuthRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        boolean nuevoEstado = !Boolean.TRUE.equals(user.getEstado());
        user.setEstado(nuevoEstado);
        userAuthRepository.save(user);

        return new MessegeGlobalDTO("Estado del usuario actualizado exitosamente");
    }

    /**
     * Obtiene un usuario por su email, utilizando caché para mejorar el
     * rendimiento.
     *
     * @param email El email del usuario
     * @return Optional con el usuario si existe, o vacío si no se encuentra
     */
    @Async
    public void enviarNotificacionLoginAsync(User user) {
        try {
            EnvioEventoNotificacionDTO eventoDTO = new EnvioEventoNotificacionDTO();
            eventoDTO.setUsuarioId(user.getId());
            eventoDTO.setEvento(EnumEventoAsociado.LOGIN_USUARIO);
            eventoDTO.setVariablesAdicionales(Map.of("username", user.getUsername(), "email", user.getEmail()));
            notificacionClient.enviarPorEvento(eventoDTO);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Obtiene un usuario por su email, utilizando caché para mejorar el
     * rendimiento.
     * 
     * @param email
     * @return
     */
    @Cacheable(value = "users", key = "#email")
    public Optional<User> findUserByEmail(String email) {
        return userAuthRepository.findByEmail(email);
    }
}