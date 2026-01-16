package com.hdh.ticketing.artist.repository;

import com.hdh.ticketing.artist.domain.Artist;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ArtistRepository extends JpaRepository<Artist, Long>{
    Page<Artist> findByNameContainingIgnoreCase(String keyword, Pageable pageable);
}
