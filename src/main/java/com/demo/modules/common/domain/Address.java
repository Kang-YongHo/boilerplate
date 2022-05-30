package com.demo.modules.common.domain;

import lombok.Getter;
import lombok.Setter;
import org.springframework.util.StringUtils;

import javax.persistence.Embeddable;

@Embeddable
@Getter
@Setter
public class Address {

    private String city;
    private String street;
    private String zipcode;

    private String lat;
    private String lng;

    public Address(String city, String street, String zipcode, String lat, String lng) {
        this.city = city;
        this.street = street;
        this.zipcode = zipcode;
        this.lat = lat;
        this.lng = lng;
    }

    public Address() {
    }
}
