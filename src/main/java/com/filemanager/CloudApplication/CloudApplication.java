package com.filemanager.CloudApplication;

import com.filemanager.CloudApplication.authentication.JwtProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication
@EnableConfigurationProperties(JwtProperties.class)

public class CloudApplication {

    public static void main(String[] args) {

        SpringApplication.run(CloudApplication.class, args);
    }

}
