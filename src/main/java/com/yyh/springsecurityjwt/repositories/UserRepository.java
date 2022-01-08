package com.yyh.springsecurityjwt.repositories;

import com.yyh.springsecurityjwt.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
}
