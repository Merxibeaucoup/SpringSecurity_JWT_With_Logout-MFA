package com.edgar.security.auth;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.edgar.security.config.JwtService;
import com.edgar.security.repository.AppUserRepository;
import com.edgar.security.repository.TokenRepository;
import com.edgar.security.token.Token;
import com.edgar.security.token.TokenType;
import com.edgar.security.user.Role;
import com.edgar.security.user.User;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Service
public class AuthenticationService {

	@Autowired
	private AppUserRepository repository;

	@Autowired
	private TokenRepository tokenRepo;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private JwtService jwtService;

	@Autowired
	private AuthenticationManager authenticationManager;

	public AuthenticationResponse register(RegisterRequest request) {

		var user = User.builder().firstname(request.getFirstname()).lastname(request.getLastname())
				.email(request.getEmail()).password(passwordEncoder.encode(request.getPassword())).role(Role.USER)
				.build();

		var savedUser = repository.save(user);

		var jwtToken = jwtService.generateToken(user);

		var refreshToken = jwtService.generateRefreshToken(user);

		saveUserToken(savedUser, jwtToken);

		return AuthenticationResponse.builder().accessToken(jwtToken).refreshToken(refreshToken).build();
	}

	public AuthenticationResponse authenticate(AuthenticationRequest request) {

		authenticationManager
				.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

		var user = repository.findByEmail(request.getEmail()).orElseThrow();

		var jwtToken = jwtService.generateToken(user);
		var refreshToken = jwtService.generateRefreshToken(user);
		revokeAllUserTokens(user);
		saveUserToken(user, jwtToken);
		return AuthenticationResponse.builder().accessToken(jwtToken).refreshToken(refreshToken).build();

	}

	private void saveUserToken(User user, String jwtToken) {
		var token = Token.builder().user(user).token(jwtToken).tokenType(TokenType.BEARER).revoked(false).expired(false)
				.build();

		tokenRepo.save(token);
	}

	private void revokeAllUserTokens(User user) {
		var validUserToken = tokenRepo.findAllValidTokensByUser(user.getId());

		if (validUserToken.isEmpty()) {
			return;
		}

		validUserToken.forEach(t -> {
			t.setExpired(true);
			t.setRevoked(true);

		});

		tokenRepo.saveAll(validUserToken);
	}

	public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {

		final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

		final String refreshToken;

		final String userEmail;

		if (authHeader == null || !authHeader.startsWith("Bearer ")) {

			return;
		}

		refreshToken = authHeader.substring(7);

		userEmail = jwtService.extractUsername(refreshToken);

		if (userEmail != null) {
			var user = this.repository.findByEmail(userEmail).orElseThrow();

			if (jwtService.isTokenValid(refreshToken, user)) {
				
				var accessToken = jwtService.generateToken(user);
				
				revokeAllUserTokens(user);
				saveUserToken(user, accessToken);
				
				var authResponse = AuthenticationResponse
						.builder()
						.accessToken(accessToken)
						.refreshToken(refreshToken)
						.build();
				
				new ObjectMapper().writeValue(response.getOutputStream(), authResponse);

			}

		}

	}

}
