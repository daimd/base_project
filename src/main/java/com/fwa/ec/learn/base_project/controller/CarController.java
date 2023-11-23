package com.fwa.ec.learn.base_project.controller;

import com.fwa.ec.learn.base_project.entity.Car;
import com.fwa.ec.learn.base_project.repository.CarRepository;
import com.fwa.ec.learn.base_project.service.GenerateTokenService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
//@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class CarController {



    private final CarRepository carRepository;

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/cars")
    public Iterable<Car> getAllCars(){
        return carRepository.findAll();
    }

    @GetMapping("{id}")
    public Car getCarById(@PathVariable("id") Car car){ // assigning using domain class convertor the id.
        return car;
    }






}
