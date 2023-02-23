package com.edgar.security.user;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.edgar.security.token.Token;

import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import lombok.Builder;

@Entity
@Builder
@Table(name ="app_user")
public class User implements UserDetails {

	

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	private String firstname;

	private String lastname;

	private String email;

	private String password;

	@Enumerated(EnumType.STRING)
	private Role role;
	
	@OneToMany(mappedBy = "user")
	private List<Token> tokens;

	public User() {

	}
	
	
	public User(Long id, String firstname, String lastname, String email, String password, Role role,
			List<Token> tokens) {
		super();
		this.id = id;
		this.firstname = firstname;
		this.lastname = lastname;
		this.email = email;
		this.password = password;
		this.role = role;
		this.tokens = tokens;
	}
	
	
	
	

	


	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getFirstname() {
		return firstname;
	}

	public void setFirstname(String firstname) {
		this.firstname = firstname;
	}

	public String getLastname() {
		return lastname;
	}

	public void setLastname(String lastname) {
		this.lastname = lastname;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	@Override
	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}
	
	public Role getRole() {
		return role;
	}


	public void setRole(Role role) {
		this.role = role;
	}


	public List<Token> getTokens() {
		return tokens;
	}


	public void setTokens(List<Token> tokens) {
		this.tokens = tokens;
	}
	
	
	
	

	/* user details methods to override */

	

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return List.of(new SimpleGrantedAuthority(role.name()));
	}

	@Override
	public String getUsername() {
		return email;
	}
	
	/* Set Everything to true  else we can't access it */

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}


	


}
