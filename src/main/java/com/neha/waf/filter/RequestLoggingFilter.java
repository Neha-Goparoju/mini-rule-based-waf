package com.neha.waf.filter;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

@Component
public class RequestLoggingFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request,
                         ServletResponse response,
                         FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String url = httpRequest.getRequestURI();
        String method = httpRequest.getMethod();
        String ip = httpRequest.getRemoteAddr();
        String userAgent = httpRequest.getHeader("User-Agent");
        String query = httpRequest.getQueryString();

        // Decode URL encoded query parameters
        if (query != null) {
            query = URLDecoder.decode(query, StandardCharsets.UTF_8);
        }

        // Log request details
        System.out.println("Request intercepted by WAF Filter");
        System.out.println("Client IP: " + ip);
        System.out.println("URL: " + url);
        System.out.println("HTTP Method: " + method);
        System.out.println("User-Agent: " + userAgent);
        System.out.println("Query Parameters: " + query);

        // List of attack patterns
        String[] attackPatterns = {
                "or 1=1",
                "union select",
                "drop table",
                "<script>",
                "alert(",
                "' or '1'='1"
        };

        // Check query parameters against attack patterns
        if (query != null) {

            String lowerQuery = query.toLowerCase();

            for (String pattern : attackPatterns) {

                if (lowerQuery.contains(pattern)) {

                    System.out.println("⚠ Possible attack detected: " + pattern);
                    System.out.println("Blocking malicious request...");

                    httpResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    httpResponse.getWriter().write("Request Blocked by WAF");

                    return;
                }
            }
        }

        // Allow safe requests
        chain.doFilter(request, response);
    }
}