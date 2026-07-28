package com.pulse_gym.ms_auth.services;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class BiometricTokenService {

    /**
     * Clave secreta para firmar tokens biométricos (misma que usa pg-ms-operation).
     * Se inyecta desde application.yaml (biometric.jwt.secret-key).
     */
    @Value("${biometric.jwt.secret-key}")
    private String secretKey;

    /**
     * Tiempo de expiración del token en milisegundos (por defecto 5 minutos).
     */
    @Value("${biometric.jwt.token-expiration:300000}")
    private Long tokenExpiration;

    /**
     * Obtiene la clave de firma a partir del Base64.
     */
    private SecretKey getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Genera un hash SHA-256 del deviceId para compararlo con el almacenado en la BD.
     * 
     * @param deviceId Identificador plano del dispositivo
     * @return Hash en formato hexadecimal, o null si deviceId es nulo/vacío
     */
    private String generateHash(String deviceId) {
        if (deviceId == null || deviceId.trim().isEmpty()) {
            return null;
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(deviceId.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            log.error("Error al generar hash SHA-256: {}", e.getMessage());
            throw new RuntimeException("Error interno al procesar la huella", e);
        }
    }

    /**
     * Genera un token JWT biométrico con los claims:
     * - userId: ID del usuario
     * - deviceId: ID del dispositivo (plano, sin hashear)
     * - exp: fecha de expiración
     * 
     * @param userId   ID del usuario
     * @param deviceId ID del dispositivo (plano)
     * @return Token JWT firmado
     */
    public String generateToken(Long userId, String deviceId) {
        // Validar entrada
        if (userId == null || userId <= 0) {
            throw new RuntimeException("ID de usuario inválido");
        }
        if (deviceId == null || deviceId.trim().isEmpty()) {
            throw new RuntimeException("DeviceId no puede estar vacío");
        }

        String hash = generateHash(deviceId);
        log.info("Generando token biométrico para userId: {}, hash: {}", userId, hash != null ? hash.substring(0, 10) + "..." : "null");

        Date now = new Date();
        Date expiration = new Date(now.getTime() + tokenExpiration);

        return Jwts.builder()
                .claim("userId", userId)
                .claim("deviceId", deviceId)
                .issuedAt(now)
                .expiration(expiration)
                .signWith(getSignKey())
                .compact();
    }
}