package com.fwa.ec.learn.base_project.repository;

import com.fwa.ec.learn.base_project.entity.Car;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CarRepository extends CrudRepository<Car, Long> {
}
