package com.smc;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.context.annotation.Bean;

import com.smc.gateway.filter.TokenAuthenticationFilter;

@EnableZuulProxy
@EnableEurekaClient
@SpringBootApplication
public class SmcGatewayApplication {

	public static void main(String[] args) {
		SpringApplication.run(SmcGatewayApplication.class, args);
	}

	@Bean
	public TokenAuthenticationFilter simpleFilter() {
		return new TokenAuthenticationFilter();
	}

}
