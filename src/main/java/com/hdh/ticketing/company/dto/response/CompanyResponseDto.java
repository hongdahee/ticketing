package com.hdh.ticketing.company.dto.response;

import com.hdh.ticketing.company.domain.Company;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class CompanyResponseDto {

    private Long id;
    private String companyName;
    private String email;
    private String ceoName;
    private String phoneNumber;
    private String address;

    public static CompanyResponseDto from(Company company) {
        return new CompanyResponseDto(
                company.getId(),
                company.getCompanyName(),
                company.getEmail(),
                company.getCeoName(),
                company.getPhoneNumber(),
                company.getAddress()
        );
    }
}