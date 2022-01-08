package com.yyh.springsecurityjwt;

import com.yyh.springsecurityjwt.domain.Role;
import com.yyh.springsecurityjwt.domain.User;
import com.yyh.springsecurityjwt.repositories.RoleRepository;
import com.yyh.springsecurityjwt.repositories.UserRepository;
import com.yyh.springsecurityjwt.services.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class SpringSecurityJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityJwtApplication.class, args);
	}

	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner run(UserService userService, UserRepository userRepository, RoleRepository roleRepository) {
		// run everytimee the application start
		return args -> {
			if(roleRepository.count() < 1) {
				userService.saveRole(new Role(null, "ROLE_USER"));
				userService.saveRole(new Role(null, "ROLE_ADMIN"));
				userService.saveRole(new Role(null, "ROLE_MANAGER"));
				userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));
			}

			if(userRepository.count() < 1) {
				userService.saveUser(new User(null, "John Wick", "John", "11111111", new ArrayList<>()));
				userService.saveUser(new User(null, "Will Smith", "Will", "11111111", new ArrayList<>()));
				userService.saveUser(new User(null, "Peter Parker", "Peter", "11111111", new ArrayList<>()));
				userService.saveUser(new User(null, "Bruce Wayne", "Bruce", "11111111", new ArrayList<>()));

				userService.addRoleToUser("John", "ROLE_USER");
				userService.addRoleToUser("John", "ROLE_MANAGER");
				userService.addRoleToUser("Will", "ROLE_ADMIN");
				userService.addRoleToUser("Peter", "ROLE_MANAGER");
				userService.addRoleToUser("Bruce", "ROLE_SUPER_ADMIN");
				userService.addRoleToUser("Bruce", "ROLE_ADMIN");
				userService.addRoleToUser("Bruce", "ROLE_USER");
			}
		};
	}
}
