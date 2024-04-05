package com.vienna.jaray;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.ServletComponentScan;

@SpringBootApplication
@ServletComponentScan
public class JarayProjectStateSecretsApplication {

    public static void main(String[] args) {
        SpringApplication.run(JarayProjectStateSecretsApplication.class, args);
    }

}
