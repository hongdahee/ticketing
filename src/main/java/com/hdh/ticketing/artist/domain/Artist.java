package com.hdh.ticketing.artist.domain;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "artist")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
public class Artist {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Enumerated(EnumType.STRING)
    @Column(name = "artist_type", nullable = false)
    private ArtistType artistType;

    @Column(name = "is_group", nullable = false)
    private boolean isGroup;

    @Column(name = "debut_date")
    private String debutDate;

    @Column(name = "profile_img")
    private String profileImg;

    public void update(String name, String description, ArtistType artistType,
                       boolean isGroup, String debutDate, String profileImg) {
        this.name = name;
        this.description = description;
        this.artistType = artistType;
        this.isGroup = isGroup;
        this.debutDate = debutDate;
        this.profileImg = profileImg;
    }
}
