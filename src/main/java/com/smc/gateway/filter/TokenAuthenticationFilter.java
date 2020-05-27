package com.smc.gateway.filter;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;

public class TokenAuthenticationFilter extends ZuulFilter {
	private static Logger logger = LoggerFactory.getLogger(TokenAuthenticationFilter.class);
	
	@Autowired
	private RestTemplate restTemplate;
	
	//business logic of filter
	@Override
	public Object run() throws ZuulException {
		//1. get request context and request self.
		RequestContext ctx = RequestContext.getCurrentContext();
	    HttpServletRequest request = ctx.getRequest();

	    logger.info(String.format("%s request to %s", request.getMethod(), request.getRequestURL().toString()));
	    
		String url = request.getRequestURL().toString();
		
	    if(url.endsWith("/api/authenticate")){
			return null;
		}
	    
	    //2. get and validate token
	    String userToken = request.getHeader("Authorization");
	    if(StringUtils.isEmpty(userToken)) {
	    	//process terminated, gate way directly return to client
	    	ctx.setSendZuulResponse(false);
	    	ctx.setResponseBody("Authorization token is null");
	    	ctx.setResponseStatusCode(401);
	    }else {
	    	//call get current user by token header api, if can get the user, pass the JWT token parser check
	    	Object user = restTemplate.getForObject("/api/currentuser", Object.class);
	    	if (user == null) {
				logger.info("The user is null...");
				ctx.setSendZuulResponse(false);
				ctx.setResponseStatusCode(401);
				ctx.setResponseBody("Invalid token or token has been expired");
			}else{
				logger.info("Login user: " + user);
				request.setAttribute("currentuser", user);
			}
	    }
		return null;
	}

	@Override
	public boolean shouldFilter() {
		return true;
	}

	//define the filter execute order, when same request encounter multiple filter
	@Override
	public int filterOrder() {
		return 1;
	}

	//define filter type = 'pre', indicate executing before request.
	@Override
	public String filterType() {
		return "pre";
	}

}
