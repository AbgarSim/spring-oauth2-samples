package com.redpanda.springoauth2jwtclient.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.reactive.function.client.WebClient;

@Controller
public class OAuthController {

  @Autowired
  private WebClient.Builder webClientBuilder;

  @GetMapping("/")
  public String home(Model model) {
    return "index";  // Thymeleaf page with the button
  }

  @GetMapping("/fetch-resource")
  public String fetchResource(@AuthenticationPrincipal OAuth2AuthorizedClient authorizedClient, Model model) {
    String accessToken = authorizedClient.getAccessToken().getTokenValue();

    // Use WebClient to fetch the secured resource
    String resourceUrl = "http://127.0.0.1:8443/resource";

    String response = webClientBuilder.baseUrl(resourceUrl)
        .defaultHeader("Authorization", "Bearer " + accessToken)
        .build()
        .get()
        .retrieve()
        .bodyToMono(String.class)
        .block();

    model.addAttribute("response", "a");
    return "resource";  // A Thymeleaf page to display the fetched resource
  }
}