package com.pulse_gym.ms_auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication(scanBasePackages = "com.pulse_gym")
@EntityScan("com.pulse_gym.lb_common.entity.auth")
@EnableFeignClients(basePackages = "com.pulse_gym.lb_common.client")
@EnableAsync
public class MsAuthApplication {

	public static void main(String[] args) {
		SpringApplication.run(MsAuthApplication.class, args);
	}

}
