package com.hdh.ticketing.artist.service;

import com.hdh.ticketing.artist.domain.Artist;
import com.hdh.ticketing.artist.dto.request.ArtistRequestDto;
import com.hdh.ticketing.artist.dto.response.ArtistResponseDto;
import com.hdh.ticketing.artist.repository.ArtistRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional
public class ArtistService {

    private final ArtistRepository artistRepository;

    public ArtistResponseDto create(ArtistRequestDto.Create req) {
        Artist saved = artistRepository.save(req.toEntity());
        return ArtistResponseDto.from(saved);
    }

    @Transactional(readOnly = true)
    public ArtistResponseDto get(Long id) {
        Artist artist = artistRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Artist not found: " + id));
        return ArtistResponseDto.from(artist);
    }

    @Transactional(readOnly = true)
    public Page<ArtistResponseDto> list(String q, Pageable pageable) {
        Page<Artist> page = (q == null || q.isBlank())
                ? artistRepository.findAll(pageable)
                : artistRepository.findByNameContainingIgnoreCase(q, pageable);

        return page.map(ArtistResponseDto::from);
    }

    @Transactional
    public ArtistResponseDto update(Long id, ArtistRequestDto.Update req) {
        Artist artist = artistRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Artist not found: " + id));

        artist.update(
                req.getName(),
                req.getDescription(),
                req.getArtistType(),
                req.getIsGroup(),
                req.getDebutDate(),
                req.getProfileImg()
        );
        return ArtistResponseDto.from(artist);
    }

    @Transactional
    public void delete(Long id) {
        if (!artistRepository.existsById(id)) {
            throw new EntityNotFoundException("Artist not found: " + id);
        }
        artistRepository.deleteById(id);
    }
}
