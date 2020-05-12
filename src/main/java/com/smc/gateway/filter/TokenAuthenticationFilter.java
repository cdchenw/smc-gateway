package com.smc.gateway.filter;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;

public class TokenAuthenticationFilter extends ZuulFilter {
	private static Logger log = LoggerFactory.getLogger(TokenAuthenticationFilter.class);
	
	//business logic of filter
	@Override
	public Object run() throws ZuulException {
		//1. get request context and request self.
		RequestContext ctx = RequestContext.getCurrentContext();
	    HttpServletRequest request = ctx.getRequest();

	    log.info(String.format("%s request to %s", request.getMethod(), request.getRequestURL().toString()));
	    
	    //2. get and validate token
	    String userToken = request.getHeader("Authorization");
	    if(StringUtils.isEmpty(userToken)) {
	    	//process terminated, gate way directly return to client
	    	ctx.setSendZuulResponse(false);
	    	ctx.setResponseBody("User token is null");
	    	ctx.setResponseStatusCode(401);
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
