package com.fwa.ec.learn.base_project;

import com.fwa.ec.learn.base_project.entity.Car;
import com.fwa.ec.learn.base_project.entity.SystemUser;
import com.fwa.ec.learn.base_project.repository.CarRepository;
import com.fwa.ec.learn.base_project.repository.SystemUserRepository;
import com.fwa.ec.learn.base_project.utils.RsaKeyProperties;
import com.fwa.ec.learn.base_project.utils.TokenLife;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
@EnableConfigurationProperties({RsaKeyProperties.class, TokenLife.class})
public class BaseProjectApplication {

    public static void main(String[] args) {
        SpringApplication.run(BaseProjectApplication.class, args);
    }


    @Bean
    CommandLineRunner commandLineRunner(CarRepository repository, SystemUserRepository userRepository, PasswordEncoder passwordEncoder){
        return genSampleData->{
          repository.save(new Car("bmw",25.5));
          repository.save(new Car("audi",19.65));
          repository.save(new Car("v",30.0));
          userRepository.save(new SystemUser("user",passwordEncoder.encode("user"),"ROLE_USER"));
          userRepository.save(new SystemUser("admin", passwordEncoder.encode("admin"), "ROLE_USER, ROLE_ADMIN"));
        };
    }

}
