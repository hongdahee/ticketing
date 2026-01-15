package com.hdh.ticketing.company.controller;

import com.hdh.ticketing.company.dto.request.CompanyRequestDto;
import com.hdh.ticketing.company.dto.response.CompanyResponseDto;
import com.hdh.ticketing.company.service.CompanyService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/company")
public class CompanyController {

    private final CompanyService companyService;

    @GetMapping("/{id}")
    public ResponseEntity<CompanyResponseDto> get(@PathVariable("id") Long id) {
        return ResponseEntity.ok(companyService.get(id));
    }

    // 예: GET /api/companies?q=sm&page=0&size=10&sort=id,desc
    @GetMapping
    public ResponseEntity<Page<CompanyResponseDto>> list(
            @RequestParam(name = "q", required = false) String q,
            Pageable pageable
    ) {
        return ResponseEntity.ok(companyService.list(q, pageable));
    }

    @PostMapping
    public ResponseEntity<CompanyResponseDto> create(@Valid @RequestBody CompanyRequestDto.Create req) {
        return ResponseEntity.ok(companyService.create(req));
    }

    @PutMapping("/{id}")
    public ResponseEntity<CompanyResponseDto> update(
            @PathVariable("id") Long id,
            @Valid @RequestBody CompanyRequestDto.Update req
    ) {
        return ResponseEntity.ok(companyService.update(id, req));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable("id") Long id) {
        companyService.delete(id);
        return ResponseEntity.noContent().build();
    }
}
