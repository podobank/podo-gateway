package com.yongy.podogateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class PodoGatewayApplication {

	public static void main(String[] args) {
		SpringApplication.run(PodoGatewayApplication.class, args);
	}

}
