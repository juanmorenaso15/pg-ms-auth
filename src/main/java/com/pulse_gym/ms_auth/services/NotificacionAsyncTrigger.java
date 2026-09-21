package com.pulse_gym.ms_auth.services;

import java.util.Map;

import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import com.pulse_gym.lb_common.client.NotificacionClient;
import com.pulse_gym.lb_common.dto.EnvioEventoNotificacionDTO;
import com.pulse_gym.lb_common.entity.auth.User;
import com.pulse_gym.lb_common.enums.EnumEventoAsociado;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Dispara los eventos de notificacion (registro, login, cambio de contraseña)
 * de forma realmente asincrona.
 *
 * Estos metodos vivian antes dentro de AuthService y se llamaban con
 * "this.metodo()" (invocacion propia): Spring implementa @Async con un proxy
 * que envuelve al bean, y ese proxy nunca se activa cuando un metodo se llama
 * a si mismo desde dentro de la misma clase, asi que @Async se ignoraba en
 * silencio y el envio corria de forma sincrona en el mismo hilo del login,
 * bloqueando la respuesta HTTP hasta que WhatsApp (via Selenium) terminara de
 * enviar. Al estar en una clase/bean distinto, la llamada si pasa por el
 * proxy y @Async funciona de verdad.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class NotificacionAsyncTrigger {

    private final NotificacionClient notificacionClient;

    @Async
    public void enviarNotificacionRegistro(User user) {
        try {
            EnvioEventoNotificacionDTO eventoDTO = new EnvioEventoNotificacionDTO();
            eventoDTO.setUsuarioId(user.getId());
            eventoDTO.setEvento(EnumEventoAsociado.REGISTRO_USUARIO);
            eventoDTO.setVariablesAdicionales(Map.of(
                    "username", user.getUsername(),
                    "email", user.getEmail(),
                    "nombre", user.getUsername(),
                    "fecha_registro", com.pulse_gym.lb_common.util.FechaUtils.ahoraColombia().toString()));
            notificacionClient.enviarPorEvento(eventoDTO);
        } catch (Exception e) {
            log.error("Error enviando notificación de registro: {}", e.getMessage());
        }
    }

    @Async
    public void enviarNotificacionLogin(User user) {
        try {
            EnvioEventoNotificacionDTO eventoDTO = new EnvioEventoNotificacionDTO();
            eventoDTO.setUsuarioId(user.getId());
            eventoDTO.setEvento(EnumEventoAsociado.LOGIN_USUARIO);
            eventoDTO.setVariablesAdicionales(Map.of("username", user.getUsername(), "email", user.getEmail()));
            notificacionClient.enviarPorEvento(eventoDTO);
        } catch (Exception e) {
            log.error("Error enviando notificación de login: {}", e.getMessage());
        }
    }

    @Async
    public void enviarNotificacionCambioContrasena(User user) {
        try {
            EnvioEventoNotificacionDTO eventoDTO = new EnvioEventoNotificacionDTO();
            eventoDTO.setUsuarioId(user.getId());
            eventoDTO.setEvento(EnumEventoAsociado.CHANGE_PASSWORD);
            eventoDTO.setVariablesAdicionales(Map.of(
                    "username", user.getUsername(),
                    "email", user.getEmail(),
                    "fecha_cambio", com.pulse_gym.lb_common.util.FechaUtils.ahoraColombia().toString()));
            notificacionClient.enviarPorEvento(eventoDTO);
        } catch (Exception e) {
            log.error("Error enviando notificación de cambio de contraseña: {}", e.getMessage());
        }
    }
}
