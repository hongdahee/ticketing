package com.hdh.ticketing.company.repository;

import com.hdh.ticketing.company.domain.Company;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CompanyRepository extends JpaRepository<Company, Long> {
    Page<Company> findByCompanyNameContainingIgnoreCase(String keyword, Pageable pageable);
}
