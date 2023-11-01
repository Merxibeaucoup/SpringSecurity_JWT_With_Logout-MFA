package com.edgar.tfa;

import org.springframework.stereotype.Service;

import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import dev.samstevens.totp.util.Utils;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class TwoFactorAuthService {
	
	
	public String generateNewSecret() {
		return new DefaultSecretGenerator().generate();
	}
	
	
	public String generateQrCodeImageURI(String secret) {
		QrData data = new QrData.Builder()
				.label("Eddie MFA practice")
				.secret(secret)
				.issuer("Edgar")
				.algorithm(HashingAlgorithm.SHA1)
				.digits(6)
				.period(30)
				.build();
		
		QrGenerator generator = new ZxingPngQrGenerator();
		
		byte[] imageData = new byte[0];
		
		try {
			imageData = generator.generate(data);
		}
		catch(QrGenerationException e) {
			e.printStackTrace();
			log.error("Error while generating QrCode : "+e.getMessage());
		}
		
		return Utils.getDataUriForImage(imageData, secret);
	}
	
	
	public boolean isOTPValid (String secret, String code) {
		TimeProvider timeProvider = new SystemTimeProvider();
		
		CodeGenerator codeGenerator = new DefaultCodeGenerator();
		
		CodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);
		
		return verifier.isValidCode(secret, code);
	}
	
	public boolean isOTPNotValid (String seecret, String code) {
		return !this.isOTPValid(seecret, code);
	}

}
