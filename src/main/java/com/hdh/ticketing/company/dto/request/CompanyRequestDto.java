package com.hdh.ticketing.company.dto.request;

import com.hdh.ticketing.company.domain.Company;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

public class CompanyRequestDto {
    @Getter
    @Setter
    public static class Create {
        @NotBlank
        private String companyName;

        @Email
        @NotBlank
        private String email;

        @NotBlank
        private String ceoName;

        @NotBlank
        private String phoneNumber;

        @NotBlank
        private String address;

        public Company toEntity() {
            return Company.builder()
                    .companyName(companyName)
                    .email(email)
                    .ceoName(ceoName)
                    .phoneNumber(phoneNumber)
                    .address(address)
                    .build();
        }
    }

    @Getter @Setter
    public static class Update {
        @NotBlank
        private String companyName;

        @Email
        private String email;

        @NotBlank
        private String ceoName;

        @NotBlank
        private String phoneNumber;

        @NotBlank
        private String address;
    }
}
