package com.redpanda.springoauth2jwtauthorizationserver.controller;

import com.redpanda.springoauth2jwtauthorizationserver.service.EmailVerificationService;
import com.redpanda.springoauth2jwtauthorizationserver.service.RegistrationService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequiredArgsConstructor
public class RegistrationController {
  private final RegistrationService registrationService;

  private final EmailVerificationService emailVerificationService;

  @GetMapping("/register")
  public String showRegistrationForm() {
    return "register";
  }

  @PostMapping("/register")
  public String registerUser(@RequestParam String email, @RequestParam String password, Model model) {
    registrationService.registerUser(email, password);
    model.addAttribute("message", "A verification email has been sent to " + email);
    return "register";
  }

  @GetMapping("/verify-email")
  public String verifyEmail(@RequestParam String token, Model model) {
    boolean success = emailVerificationService.verifyToken(token);
    model.addAttribute("message", success ? "Email verified!" : "Invalid token!");
    return "verify";
  }
}
