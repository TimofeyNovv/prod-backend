package ru.exmaple.prodbackend.demo.controller;

import io.swagger.v3.oas.annotations.Operation;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/demo")
@RequiredArgsConstructor
public class DemoController {

    @Operation(
            summary = "ping pong"
    )
    @GetMapping("/ping")
    public ResponseEntity<?> ping(){
        return ResponseEntity.ok("pong");
    }
}
