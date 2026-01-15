package com.hdh.ticketing.company.service;

import com.hdh.ticketing.company.domain.Company;
import com.hdh.ticketing.company.dto.request.CompanyRequestDto;
import com.hdh.ticketing.company.dto.response.CompanyResponseDto;
import com.hdh.ticketing.company.repository.CompanyRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional
public class CompanyService {

    private final CompanyRepository companyRepository;

    public CompanyResponseDto create(CompanyRequestDto.Create req) {
        Company saved = companyRepository.save(req.toEntity());
        return CompanyResponseDto.from(saved);
    }

    @Transactional(readOnly = true)
    public CompanyResponseDto get(Long id) {
        Company company = companyRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Company not found: " + id));
        return CompanyResponseDto.from(company);
    }


    @Transactional(readOnly = true)
    public Page<CompanyResponseDto> list(String keyword, Pageable pageable) {
        Page<Company> page = (keyword == null || keyword.isBlank())
                ? companyRepository.findAll(pageable)
                : companyRepository.findByCompanyNameContainingIgnoreCase(keyword, pageable);

        return page.map(CompanyResponseDto::from);
    }

    public CompanyResponseDto update(Long id, CompanyRequestDto.Update req) {
        Company company = companyRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Company not found: " + id));

        company.update(req.getCompanyName(), req.getEmail(), req.getCeoName(), req.getPhoneNumber(), req.getAddress());
        return CompanyResponseDto.from(company);
    }

    public void delete(Long id) {
        if (!companyRepository.existsById(id)) {
            throw new EntityNotFoundException("Company not found: " + id);
        }
        companyRepository.deleteById(id);
    }
}
