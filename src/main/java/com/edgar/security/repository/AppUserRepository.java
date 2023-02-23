package com.edgar.security.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.edgar.security.user.User;

@Repository
public interface AppUserRepository extends JpaRepository<User, Long> {
	
	Optional<User> findByEmail(String email);

}
