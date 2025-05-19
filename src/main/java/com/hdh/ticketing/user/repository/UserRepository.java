package com.hdh.ticketing.user.repository;

import com.hdh.ticketing.user.domain.SiteUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<SiteUser, Long> {
}
