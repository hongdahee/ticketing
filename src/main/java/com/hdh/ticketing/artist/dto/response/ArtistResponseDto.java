package com.hdh.ticketing.artist.dto.response;

import com.hdh.ticketing.artist.domain.Artist;
import com.hdh.ticketing.artist.domain.ArtistType;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class ArtistResponseDto {
    private Long id;
    private String name;
    private String description;
    private ArtistType artistType;
    private boolean isGroup;
    private String debutDate;
    private String profileImg;

    public static ArtistResponseDto from(Artist artist) {
        return new ArtistResponseDto(
                artist.getId(),
                artist.getName(),
                artist.getDescription(),
                artist.getArtistType(),
                artist.isGroup(),
                artist.getDebutDate(),
                artist.getProfileImg()
        );
    }
}
