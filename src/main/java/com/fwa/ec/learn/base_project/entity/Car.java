package com.fwa.ec.learn.base_project.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@NoArgsConstructor
@Table(name = "test_car")
@Getter
@Setter
public class Car {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    private String make;
    private Double cost;
    private LocalDateTime manufacturedOn;
    private LocalDateTime purchasedOn;

    public Car(String make, Double cost){
        this.cost= cost;
        this.make = make;
    }

    @Override
    public String toString() {
        return "Car{" +
                "id=" + id +
                ", make='" + make + '\'' +
                ", cost=" + cost +
                ", manufacturedOn=" + manufacturedOn +
                ", purchasedOn=" + purchasedOn +
                '}';
    }
}
