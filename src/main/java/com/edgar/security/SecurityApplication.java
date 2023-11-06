package com.edgar.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import com.edgar.tfa.TwoFactorAuthService;

@SpringBootApplication
public class SecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityApplication.class, args);
	}
	
	@Bean
    public TwoFactorAuthService twoFactorAuthService() {
        return new TwoFactorAuthService();
    }

}
