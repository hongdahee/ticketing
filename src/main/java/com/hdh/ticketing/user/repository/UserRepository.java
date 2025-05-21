package com.hdh.ticketing.user.repository;

import com.hdh.ticketing.user.domain.SiteUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<SiteUser, Long> {
    Optional<SiteUser> findByEmail(String email);
    Optional<SiteUser> findByUsername(String username);

    boolean existsByEmail(String email);
}
