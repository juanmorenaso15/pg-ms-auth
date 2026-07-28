package com.pulse_gym.ms_auth.services;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.pulse_gym.lb_common.client.AuthServiceClient;
import com.pulse_gym.lb_common.client.NotificacionClient;
import com.pulse_gym.lb_common.client.UsuarioClient;
import com.pulse_gym.lb_common.dto.ChangePasswordRequestDTO;
import com.pulse_gym.lb_common.dto.ContrasenaOlvidada;
import com.pulse_gym.lb_common.dto.EnvioEventoNotificacionDTO;
import com.pulse_gym.lb_common.dto.HttpGlobalResponse;
import com.pulse_gym.lb_common.dto.JwtDTO;
import com.pulse_gym.lb_common.dto.MessegeGlobalDTO;
import com.pulse_gym.lb_common.dto.RestablecerContrasena;
import com.pulse_gym.lb_common.dto.UsuarioPerfilResponseDTO;
import com.pulse_gym.lb_common.entity.auth.PasswordResetToken;
import com.pulse_gym.lb_common.entity.auth.User;
import com.pulse_gym.lb_common.enums.EnumEventoAsociado;
import com.pulse_gym.lb_common.services.BiometricJwtService;
import com.pulse_gym.lb_common.services.JwtService;
import com.pulse_gym.ms_auth.dto.LoginRequestDTO;
import com.pulse_gym.ms_auth.dto.RegisterRequestDTO;
import com.pulse_gym.ms_auth.repository.PasswordResetTokenRepository;
import com.pulse_gym.ms_auth.repository.UserAuthRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

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

    /** Cliente para interactuar con el servicio de autenticación */
    private final AuthServiceClient authServiceClient;

    /** Servicio para generación y validación de tokens biométricos */
    private final BiometricJwtService biometricJwtService;

    /**
     * Cliente para interactuar con el microservicio de usuarios (pg-ms-users)
     */
    private final UsuarioClient usuarioClient;

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
        logger.info("=== PASO 1: Iniciando registro para email: {} ===", requestDTO.getEmail());

        if (userAuthRepository.findByEmail(requestDTO.getEmail()).isPresent()) {
            logger.warn("=== PASO 2: Email ya existe: {} ===", requestDTO.getEmail());
            return new MessegeGlobalDTO("El correo ya esta en uso");
        }

        if (userAuthRepository.findByUsername(requestDTO.getUsername()).isPresent()) {
            return new MessegeGlobalDTO("El nombre de usuario ya está en uso");
        }

        logger.info("=== PASO 3: Creando usuario ===");
        User user = new User();
        user.setEmail(requestDTO.getEmail());
        user.setPassword(passwordEncoder.encode(requestDTO.getPassword()));
        user.setUsername(requestDTO.getUsername());
        user.setRol(requestDTO.getRol());
        user.setEstado(requestDTO.getEstado());
        user.setFechaRegistro(LocalDateTime.now());

        logger.info("=== PASO 4: Guardando usuario en BD ===");
        userAuthRepository.save(user);
        logger.info("=== PASO 5: Usuario guardado con ID: {} ===", user.getId());

        logger.info("=== PASO 6: Verificando notificacionClient, es null? {} ===", notificacionClient == null);

        if (notificacionClient != null) {
            logger.info("=== PASO 7: Llamando a enviarNotificacionRegistro ===");
            enviarNotificacionRegistro(user);
            logger.info("=== PASO 8: enviarNotificacionRegistro finalizado ===");
        } else {
            logger.error("=== PASO 8 ERROR: notificacionClient es NULL ===");
        }

        logger.info("=== PASO 9: Registro completado exitosamente ===");
        return new MessegeGlobalDTO("Se ha registrado correctamente");
    }

    /**
     * Envía notificación de registro al microservicio de notificaciones.
     *
     * @param user Usuario recién registrado
     */
    private void enviarNotificacionRegistro(User user) {
        try {
            logger.info(">>> INICIANDO envío de notificación de registro para usuario: {}", user.getEmail());
            logger.info(">>> ID de usuario: {}", user.getId());
            logger.info(">>> Evento: {}", EnumEventoAsociado.REGISTRO_USUARIO);

            EnvioEventoNotificacionDTO eventoDTO = new EnvioEventoNotificacionDTO();
            eventoDTO.setUsuarioId(user.getId());
            eventoDTO.setEvento(EnumEventoAsociado.REGISTRO_USUARIO);
            eventoDTO.setVariablesAdicionales(Map.of(
                    "username", user.getUsername(),
                    "email", user.getEmail(),
                    "nombre", user.getUsername(),
                    "fecha_registro", LocalDateTime.now().toString()));

            logger.info(">>> Llamando a notificacionClient.enviarPorEvento con DTO: {}", eventoDTO);

            Map<String, Object> respuesta = notificacionClient.enviarPorEvento(eventoDTO);
            logger.info(">>> Respuesta de notificacionClient: {}", respuesta);

            logger.info(">>> Notificación de registro enviada exitosamente");
        } catch (Exception e) {
            logger.error(">>> ERROR CRÍTICO al enviar notificación: {}", e.getMessage(), e);
            e.printStackTrace();
        }
    }

    /**
     * Inicia sesión de un usuario existente.
     * Valida credenciales y genera token JWT.
     *
     * @param requestDTO Credenciales de login (email, password)
     * @return Respuesta con token JWT y mensaje de éxito o error
     */
    public HttpGlobalResponse<JwtDTO> login(LoginRequestDTO requestDTO) {
        logger.info("=== LOGIN: Iniciando login para email: {} ===", requestDTO.getEmail());

        HttpGlobalResponse<JwtDTO> response = new HttpGlobalResponse<>();
        Optional<User> userFound = userAuthRepository.findByEmail(requestDTO.getEmail());

        if (userFound.isEmpty()) {
            logger.warn("=== LOGIN: Usuario no encontrado: {} ===", requestDTO.getEmail());
            response.setMessage("Este usuario no se encuentra registrado");
            return response;
        }

        User user = userFound.get();

        if (!passwordEncoder.matches(requestDTO.getPassword(), user.getPassword())) {
            logger.warn("=== LOGIN: Contraseña incorrecta para email: {} ===", requestDTO.getEmail());
            response.setMessage("Correo o contraseña son incorrectos");
            return response;
        }

        logger.info("=== LOGIN: Credenciales válidas, generando token para usuario ID: {} ===", user.getId());

        JwtDTO jwtDTO = new JwtDTO();
        String jwt = jwtService.generateToken(user.getId(), user.getRol().name(), user.getEmail());
        jwtDTO.setJwt(jwt);
        response.setMessage("Inicio de sesion exitoso");
        response.setData(jwtDTO);

        logger.info("=== LOGIN: Verificando notificacionClient para login, es null? {} ===",
                notificacionClient == null);

        if (notificacionClient != null) {
            logger.info("=== LOGIN: Llamando a enviarNotificacionLogin ===");
            enviarNotificacionLogin(user);
            logger.info("=== LOGIN: enviarNotificacionLogin finalizado ===");
        } else {
            logger.error("=== LOGIN ERROR: notificacionClient es NULL ===");
        }

        return response;
    }

    /**
     * Envía notificación de inicio de sesión al microservicio de notificaciones.
     *
     * @param user Usuario que inició sesión
     */
    private void enviarNotificacionLogin(User user) {
        try {
            logger.info(">>> Enviando notificación de login para usuario: {}", user.getEmail());

            EnvioEventoNotificacionDTO eventoDTO = new EnvioEventoNotificacionDTO();
            eventoDTO.setUsuarioId(user.getId());
            eventoDTO.setEvento(EnumEventoAsociado.LOGIN_USUARIO);
            eventoDTO.setVariablesAdicionales(Map.of(
                    "username", user.getUsername(),
                    "email", user.getEmail()));

            logger.info(">>> Llamando a notificacionClient.enviarPorEvento para login");

            Map<String, Object> respuesta = notificacionClient.enviarPorEvento(eventoDTO);
            logger.info(">>> Respuesta de notificacionClient login: {}", respuesta);

            logger.info(">>> Notificación de login enviada exitosamente para usuario: {}", user.getEmail());
        } catch (Exception e) {
            logger.error(">>> Error al enviar notificación de login para usuario {}: {}", user.getEmail(),
                    e.getMessage(), e);
        }
    }

    /**
     * Refresca un token JWT que está cerca de expirar.
     *
     * @param token Token JWT actual
     * @return Nuevo token JWT renovado
     * @throws Exception Si el token es inválido o está expirado
     */
    public JwtDTO refreshToken(String token) throws Exception {
        logger.info("=== REFRESH: Refrescando token ===");
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
        logger.info("=== FORGOT PASSWORD: Solicitud para username: {} ===", requestDTO.getUsername());

        Optional<User> userOpt = userAuthRepository.findByUsername(requestDTO.getUsername());

        if (userOpt.isEmpty()) {
            logger.warn("=== FORGOT PASSWORD: Username no encontrado: {} ===", requestDTO.getUsername());
            return new MessegeGlobalDTO("Si el username existe, recibirás un email con instrucciones");
        }

        User user = userOpt.get();
        logger.info("=== FORGOT PASSWORD: Usuario encontrado con ID: {} ===", user.getId());

        tokenRepository.deleteByUserId(user.getId());

        String token = generateOTP();
        logger.info("=== FORGOT PASSWORD: Token OTP generado: {} ===", token);

        PasswordResetToken resetToken = new PasswordResetToken();
        resetToken.setToken(token);
        resetToken.setUser(user);
        resetToken.setExpiryDate(LocalDateTime.now().plusMinutes(tokenExpirationMinutes));
        resetToken.setUsed(false);

        tokenRepository.save(resetToken);
        logger.info("=== FORGOT PASSWORD: Token guardado en BD ===");

        emailService.sendPasswordResetEmailSimple(user.getEmail(), user.getUsername(), token);
        logger.info("=== FORGOT PASSWORD: Email enviado a: {} ===", user.getEmail());

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
        logger.info("=== RESET PASSWORD: Iniciando restablecimiento ===");

        if (!requestDTO.getNewPassword().equals(requestDTO.getConfirmPassword())) {
            logger.warn("=== RESET PASSWORD: Las contraseñas no coinciden ===");
            return new MessegeGlobalDTO("Las contraseñas no coinciden");
        }

        Optional<PasswordResetToken> tokenOpt = tokenRepository.findByToken(requestDTO.getToken());

        if (tokenOpt.isEmpty()) {
            logger.warn("=== RESET PASSWORD: Token no encontrado: {} ===", requestDTO.getToken());
            return new MessegeGlobalDTO("Token inválido o expirado");
        }

        PasswordResetToken resetToken = tokenOpt.get();

        if (resetToken.isUsed()) {
            logger.warn("=== RESET PASSWORD: Token ya utilizado ===");
            return new MessegeGlobalDTO("Este token ya ha sido utilizado");
        }

        if (resetToken.isExpired()) {
            logger.warn("=== RESET PASSWORD: Token expirado ===");
            return new MessegeGlobalDTO("El token ha expirado");
        }

        User user = resetToken.getUser();
        logger.info("=== RESET PASSWORD: Token válido para usuario ID: {} ===", user.getId());

        user.setPassword(passwordEncoder.encode(requestDTO.getNewPassword()));
        userAuthRepository.save(user);
        logger.info("=== RESET PASSWORD: Contraseña actualizada ===");

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
        logger.info("[HUELLA] Inicio de autenticación biométrica");

        HttpGlobalResponse<JwtDTO> response = new HttpGlobalResponse<>();

        if (!biometricJwtService.validateToken(biometricToken)) {
            logger.warn("[HUELLA] Token biométrico inválido");
            response.setMessage("Huella no reconocida. Intente de nuevo o use otro método.");
            return response;
        }

        if (biometricJwtService.isTokenExpired(biometricToken)) {
            logger.warn("[HUELLA] Token biométrico expirado");
            response.setMessage("Huella no reconocida. Intente de nuevo o use otro método.");
            return response;
        }

        Long userId = biometricJwtService.extractUserId(biometricToken);
        String deviceId = biometricJwtService.extractDeviceId(biometricToken);

        if (userId == null || deviceId == null) {
            logger.warn("[HUELLA] Token biométrico incompleto - userId: {}, deviceId: {}", userId, deviceId);
            response.setMessage("Huella no reconocida. Intente de nuevo o use otro método.");
            return response;
        }

        logger.info("[HUELLA] Token válido para userId: {}, deviceId: {}", userId, deviceId);

        UsuarioPerfilResponseDTO usuarioPerfil;
        try {
            usuarioPerfil = usuarioClient.obtenerUsuarioPorIdInterno(userId);
        } catch (Exception e) {
            logger.error("[HUELLA] Error al consultar usuario en pg-ms-users: {}", e.getMessage());
            response.setMessage("Error interno al validar la huella");
            return response;
        }

        if (usuarioPerfil == null) {
            logger.warn("[HUELLA] Usuario no encontrado: {}", userId);
            response.setMessage("Huella no reconocida. Intente de nuevo o use otro método.");
            return response;
        }

        if (usuarioPerfil.getEstado() == null ||
                !usuarioPerfil.getEstado().name().equalsIgnoreCase("ACTIVO")) {
            logger.warn("[HUELLA] Usuario inactivo: {}", userId);
            response.setMessage("Usuario inactivo. Contacte con administración.");
            return response;
        }

        String hashGuardado = usuarioPerfil.getBiometricDeviceId();
        if (hashGuardado == null || hashGuardado.trim().isEmpty()) {
            logger.warn("[HUELLA] Usuario sin huella registrada: {}", userId);
            response.setMessage("Huella no reconocida. Intente de nuevo o use otro método.");
            return response;
        }

        String hashDeviceIdToken = biometricJwtService.generateHash(deviceId);
        if (hashDeviceIdToken == null || !hashDeviceIdToken.equals(hashGuardado)) {
            logger.warn("[HUELLA] Hash no coincide para usuario: {}. Hash esperado: {}, hash recibido: {}",
                    userId, hashGuardado.substring(0, 10) + "...",
                    hashDeviceIdToken != null ? hashDeviceIdToken.substring(0, 10) + "..." : "null");
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

        logger.info("[HUELLA] Autenticación biométrica exitosa para usuario: {}", userId);

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
        logger.info("[PASSWORD] Inicio de cambio de contraseña para usuario ID: {}", userId);

        // 1. Buscar usuario
        User user = userAuthRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        // 2. Validar contraseña actual
        if (!passwordEncoder.matches(requestDTO.getCurrentPassword(), user.getPassword())) {
            logger.warn("[PASSWORD] Contraseña actual incorrecta para usuario ID: {}", userId);
            throw new RuntimeException("La contraseña actual es incorrecta");
        }

        // 3. Validar que nueva contraseña coincida con confirmación
        if (!requestDTO.getNewPassword().equals(requestDTO.getConfirmPassword())) {
            logger.warn("[PASSWORD] Las contraseñas no coinciden para usuario ID: {}", userId);
            throw new RuntimeException("La nueva contraseña y la confirmación no coinciden");
        }

        // 4. Validar que la nueva contraseña no sea igual a la actual
        if (passwordEncoder.matches(requestDTO.getNewPassword(), user.getPassword())) {
            logger.warn("[PASSWORD] La nueva contraseña es igual a la actual para usuario ID: {}", userId);
            throw new RuntimeException("La nueva contraseña no puede ser igual a la actual");
        }

        // 5. Encriptar nueva contraseña con BCrypt
        String encodedPassword = passwordEncoder.encode(requestDTO.getNewPassword());

        // 6. Actualizar en BD
        user.setPassword(encodedPassword);
        userAuthRepository.save(user);

        // 7. Log estructurado
        logger.info("[PASSWORD] Contraseña actualizada exitosamente para usuario ID: {}", userId);

        return new MessegeGlobalDTO("Contraseña actualizada exitosamente");
    }
}