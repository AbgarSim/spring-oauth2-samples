package com.redpanda.resource.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourceController {


  @GetMapping("/resource")
  public String resource(){
    return "This is protected resource!";
  }
}
