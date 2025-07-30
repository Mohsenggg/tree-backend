package com.mgh.backend.business.member.entity;


import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "members")
public class memberEntity {

    @Id
    private Long id;

    private String name;
    private Double x;
    private Double y;


}
