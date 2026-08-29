package com.pulse_gym.ms_auth.services;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    /** Cliente para enviar correos electrónicos */
    private final JavaMailSender mailSender;

    /** Correo electrónico remitente configurado en application.yaml */
    @Value("${spring.mail.username}")
    private String fromEmail;

    // @Value("${app.frontend-url:http://localhost:3000}")
    // private String frontendUrl;

    /**
     * 
     * Envía un email de recuperación de contraseña en formato HTML.
     * 
     * @param to       Email del destinatario
     * @param username Nombre del usuario
     * @param token    Token de verificación
     */
    public void sendPasswordResetEmailSimple(String to, String username, String token) {
        // Validar que los valores no sean nulos
        if (to == null || to.isBlank()) {
            throw new RuntimeException("El email del destinatario no puede estar vacío");
        }
        if (username == null || username.isBlank()) {
            throw new RuntimeException("El nombre de usuario no puede estar vacío");
        }
        if (token == null || token.isBlank()) {
            throw new RuntimeException("El token no puede estar vacío");
        }

        try {
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(to);
            helper.setSubject("Restablecimiento de contraseña - Pulse Gym");

            String htmlContent = String.format(
                    """
                            <!DOCTYPE html>
                            <html>
                            <head>
                                <meta charset="UTF-8">
                                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                                <title>Restablecer contraseña - Pulse Gym</title>
                                <style>
                                    body {
                                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                                        line-height: 1.6;
                                        color: #2c3e50;
                                        margin: 0;
                                        padding: 0;
                                        background: linear-gradient(135deg, #e0eafc 0%%, #cfdef3 100%%);
                                    }
                                    .container {
                                        max-width: 550px;
                                        margin: 30px auto;
                                        padding: 0;
                                        background-color: #ffffff;
                                        border-radius: 20px;
                                        box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
                                        overflow: hidden;
                                    }
                                    .header {
                                        background: linear-gradient(135deg, #2c4b77 0%%, #8bb5d6 100%%);
                                        color: white;
                                        padding: 35px 20px;
                                        text-align: center;
                                    }
                                    .header h1 {
                                        margin: 0;
                                        font-size: 28px;
                                        font-weight: 300;
                                        letter-spacing: 1px;
                                    }
                                    .header p {
                                        margin: 10px 0 0;
                                        opacity: 0.9;
                                        font-size: 14px;
                                    }
                                    .content {
                                        padding: 40px 35px;
                                        background-color: #ffffff;
                                    }
                                    .greeting {
                                        font-size: 20px;
                                        color: #2c3e50;
                                        margin-bottom: 20px;
                                        font-weight: 500;
                                    }
                                    .message {
                                        color: #5d6d7e;
                                        margin-bottom: 25px;
                                        font-size: 15px;
                                        line-height: 1.5;
                                    }
                                    .code-container {
                                        background: #f0f4f8;
                                        padding: 30px;
                                        border-radius: 16px;
                                        text-align: center;
                                        margin: 30px 0;
                                        border: 1px solid #dce6f0;
                                    }
                                    .code-label {
                                        font-size: 12px;
                                        color: #6c8ebf;
                                        text-transform: uppercase;
                                        letter-spacing: 3px;
                                        margin-bottom: 15px;
                                        font-weight: 600;
                                    }
                                    .code {
                                        font-size: 48px;
                                        font-weight: 600;
                                        color: #0b315c;
                                        letter-spacing: 10px;
                                        background: white;
                                        display: inline-block;
                                        padding: 15px 30px;
                                        border-radius: 12px;
                                        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
                                        border: 1px solid #dce6f0;
                                    }
                                    .expiry {
                                        font-size: 12px;
                                        color: #2d5a8f;
                                        margin-top: 15px;
                                    }
                                    .warning-box {
                                        background-color: #f8f9fc;
                                        border-left: 3px solid #6c8ebf;
                                        padding: 15px 20px;
                                        margin: 25px 0;
                                        border-radius: 8px;
                                    }
                                    .warning-text {
                                        color: #7a8b9e;
                                        font-size: 12px;
                                        margin: 0;
                                        line-height: 1.4;
                                    }
                                    .footer {
                                        background-color: #f8f9fc;
                                        padding: 20px 30px;
                                        text-align: center;
                                        border-top: 1px solid #e8edf2;
                                    }
                                    .footer-text {
                                        color: #9aabbb;
                                        font-size: 11px;
                                        margin: 5px 0;
                                    }
                                    .highlight {
                                        color: #6c8ebf;
                                        text-decoration: none;
                                    }
                                </style>
                            </head>
                            <body>
                                <div class="container">
                                    <div class="header">
                                        <h1> <strong>Pulse Gym</strong> </h1>
                                        <p>Tu bienestar, nuestra pasión</p>
                                    </div>

                                    <div class="content">
                                        <div class="greeting">
                                            Estimado(a) <strong>%s</strong>,
                                        </div>

                                        <div class="message">
                                            Hemos recibido una solicitud para restablecer la contraseña de tu cuenta en <strong>Pulse Gym</strong>.
                                            Para garantizar la seguridad de tu cuenta, utiliza el siguiente código de verificación:
                                        </div>

                                        <div class="code-container">
                                            <div class="code-label">CÓDIGO DE VERIFICACIÓN</div>
                                            <div class="code">%s</div>
                                            <div class="expiry">
                                                Válido por <strong>10 minutos</strong>
                                            </div>
                                        </div>

                                        <div class="warning-box">
                                            <div class="warning-text">
                                                <strong>ℹ️ Importante:</strong> Si no solicitaste este cambio, por favor ignora este mensaje.
                                                Tu contraseña permanecerá segura y sin cambios.
                                            </div>
                                        </div>

                                    </div>

                                    <div class="footer">
                                        <div class="footer-text">
                                            © 2026 Pulse Gym - Todos los derechos reservados
                                        </div>
                                        <div class="footer-text">
                                            Este es un mensaje automático, por favor no responder a este correo
                                        </div>
                                        <div class="footer-text">
                                            <span class="highlight">Pulse Gym</span> - Donde los sueños se convierten en metas
                                        </div>
                                    </div>
                                </div>
                            </body>
                            </html>
                            """,
                    username, token);

            helper.setText(htmlContent, true);
            mailSender.send(mimeMessage);

            log.info("Email enviado exitosamente a: {}", to);

        } catch (MessagingException e) {
            log.error("Error al enviar email HTML a {}: {}", to, e.getMessage());
            throw new RuntimeException("No se pudo enviar el email de recuperación", e);
        }
    }

    /**
     * Envía un email con la contraseña temporal generada por administración.
     * 
     * @param to                 Email del destinatario
     * @param username           Nombre del usuario
     * @param contrasenaTemporal Contraseña temporal generada
     */
    public void sendTemporaryPasswordEmail(String to, String username, String contrasenaTemporal) {
        if (to == null || to.isBlank()) {
            throw new RuntimeException("El email del destinatario no puede estar vacío");
        }

        try {
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(to);
            helper.setSubject("Acceso Temporal - Pulse Gym");

            String htmlContent = String.format(
                    """
                            <!DOCTYPE html>
                            <html>
                            <head>
                                <meta charset="UTF-8">
                                <style>
                                    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #2c3e50; background-color: #f4f6fa; margin: 0; padding: 20px; }
                                    .container { max-width: 550px; margin: 0 auto; background-color: #ffffff; border-radius: 16px; box-shadow: 0 10px 25px rgba(0,0,0,0.05); overflow: hidden; }
                                    .header { background: #051f42; color: white; padding: 30px 20px; text-align: center; }
                                    .header h1 { margin: 0; font-size: 24px; }
                                    .content { padding: 30px; }
                                    .temp-key-box { background: #f1f5f9; border: 2px dashed #051f42; border-radius: 10px; padding: 16px; text-align: center; font-size: 22px; font-weight: bold; color: #051f42; letter-spacing: 3px; margin: 20px 0; }
                                    .footer { background: #f8fafc; padding: 20px; text-align: center; font-size: 12px; color: #94a3b8; border-top: 1px solid #e2e8f0; }
                                </style>
                            </head>
                            <body>
                                <div class="container">
                                    <div class="header">
                                        <h1>Pulse Gym</h1>
                                        <p style="margin: 5px 0 0; opacity: 0.8; font-size: 13px;">Reestablecimiento de acceso</p>
                                    </div>
                                    <div class="content">
                                        <p style="font-size: 16px;">Hola <strong>%s</strong>,</p>
                                        <p>Un administrador ha generado una <strong>contraseña temporal</strong> de un solo uso para tu cuenta.</p>
                                        <p>Utiliza la siguiente clave para iniciar sesión:</p>

                                        <div class="temp-key-box">%s</div>

                                        <p style="font-size: 13px; color: #64748b;"><strong>Nota:</strong> Al ingresar con esta clave, el sistema te solicitará cambiarla obligatoriamente por una nueva contraseña de tu preferencia.</p>
                                    </div>
                                    <div class="footer">
                                        © 2026 Pulse Gym - Todos los derechos reservados.
                                    </div>
                                </div>
                            </body>
                            </html>
                            """,
                    username, contrasenaTemporal);

            helper.setText(htmlContent, true);
            mailSender.send(mimeMessage);

            log.info("Email de clave temporal enviado exitosamente a: {}", to);
        } catch (MessagingException e) {
            log.error("Error al enviar email de clave temporal a {}: {}", to, e.getMessage());
            throw new RuntimeException("No se pudo enviar el correo con la contraseña temporal", e);
        }
    }
}
