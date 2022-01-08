package com.yyh.springsecurityjwt.repositories;

import com.yyh.springsecurityjwt.domain.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Role findByName(String name);
}
