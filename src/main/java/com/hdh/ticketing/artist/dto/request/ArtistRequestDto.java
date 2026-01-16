package com.hdh.ticketing.artist.dto.request;

import com.hdh.ticketing.artist.domain.Artist;
import com.hdh.ticketing.artist.domain.ArtistType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

public class ArtistRequestDto {
    @Getter
    @Setter
    public static class Create {
        @NotBlank
        private String name;

        private String description;

        @NotNull
        private ArtistType artistType;

        @NotNull
        private Boolean isGroup;

        private String debutDate;
        private String profileImg;

        public Artist toEntity() {
            return Artist.builder()
                    .name(name)
                    .description(description)
                    .artistType(artistType)
                    .isGroup(isGroup)
                    .debutDate(debutDate)
                    .profileImg(profileImg)
                    .build();
        }
    }

    @Getter @Setter
    public static class Update {
        @NotBlank
        private String name;

        private String description;

        @NotNull
        private ArtistType artistType;

        @NotNull
        private Boolean isGroup;

        private String debutDate;
        private String profileImg;
    }
}
