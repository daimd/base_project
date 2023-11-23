package com.fwa.ec.learn.base_project.repository;

import com.fwa.ec.learn.base_project.entity.SystemUser;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface SystemUserRepository  extends CrudRepository<SystemUser, Long> {
    Optional<SystemUser> findAllByUsername(String username);

}
