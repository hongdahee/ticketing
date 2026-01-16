package com.hdh.ticketing.artist.controller;

import com.hdh.ticketing.artist.dto.request.ArtistRequestDto;
import com.hdh.ticketing.artist.dto.response.ArtistResponseDto;
import com.hdh.ticketing.artist.service.ArtistService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/artist")
@RequiredArgsConstructor
public class ArtistController {

    private final ArtistService artistService;

    @PostMapping
    public ResponseEntity<ArtistResponseDto> create(@Valid @RequestBody ArtistRequestDto.Create req) {
        return ResponseEntity.ok(artistService.create(req));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ArtistResponseDto> get(@PathVariable("id") Long id) {
        return ResponseEntity.ok(artistService.get(id));
    }

    @GetMapping
    public ResponseEntity<Page<ArtistResponseDto>> list(
            @RequestParam(name = "q", required = false) String q,
            Pageable pageable
    ) {
        return ResponseEntity.ok(artistService.list(q, pageable));
    }

    @PutMapping("/{id}")
    public ResponseEntity<ArtistResponseDto> update(
            @PathVariable("id") Long id,
            @Valid @RequestBody ArtistRequestDto.Update req
    ) {
        return ResponseEntity.ok(artistService.update(id, req));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable("id") Long id) {
        artistService.delete(id);
        return ResponseEntity.noContent().build();
    }
}
