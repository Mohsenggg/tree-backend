package com.mgh.backend.auth.repository;

import com.mgh.backend.auth.domain.entity.UserAuth;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;


@Repository
public interface UserAuthRepo extends JpaRepository<UserAuth, Long> {
    Optional<UserAuth> findByUsername(String username);

    boolean existsByUsernameIgnoreCase(String username);

    boolean existsByEmailIgnoreCase(String email);

    boolean existsByPhone(String phone);
}
