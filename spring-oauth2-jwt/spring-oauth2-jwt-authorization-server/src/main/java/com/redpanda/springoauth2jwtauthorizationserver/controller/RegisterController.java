package com.redpanda.springoauth2jwtauthorizationserver.controller;

import com.redpanda.springoauth2jwtauthorizationserver.service.RegisterService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequiredArgsConstructor
public class RegisterController {
//
//  private final RegisterService registerService;
//
////  @GetMapping("/login")
////  public String showLoginPage() {
////    return "login";
////  }
//
//  @GetMapping("/register")
//  public String showRegistrationForm() {
//    return "register"; // Points to register.html
//  }
//
//  @PostMapping("/register")
//  public String registerUser(@RequestParam String username,
//                             @RequestParam String password,
//                             @RequestParam String repeatPassword,
//                             RedirectAttributes redirectAttributes) {
//
//    // Check if passwords match
//    if (!password.equals(repeatPassword)) {
//      redirectAttributes.addAttribute("passwordMismatch", true);
//      return "redirect:/register";
//    }
//
//    // Attempt to register the user
//    registerService.registerUser(username, password);
//    return "redirect:/login?registered";
//  }
//
//  @GetMapping("/recover")
//  public String recover() {
//    return "recover";
//  }


}
