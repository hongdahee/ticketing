package com.hdh.ticketing.company.domain;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "company")
@Builder
@AllArgsConstructor
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Company {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "company_name", nullable = false)
    private String companyName;

    @Column(nullable = false)
    private String email;

    @Column(name = "ceo_name", nullable = false)
    private String ceoName;

    @Column(name = "phone_number", nullable = false)
    private String phoneNumber;

    @Column(nullable = false)
    private String address;

    public void update(String companyName, String email, String ceoName, String phoneNumber, String address) {
        this.companyName = companyName;
        this.email = email;
        this.ceoName = ceoName;
        this.phoneNumber = phoneNumber;
        this.address = address;
    }
}
