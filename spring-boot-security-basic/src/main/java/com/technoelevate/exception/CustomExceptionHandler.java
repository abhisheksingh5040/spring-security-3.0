package com.technoelevate.exception;


import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 1. Bad Credential : Authentication Failure : 401
 * 2. Access denied : Authorization ERROR : 403
 * 3. Invalid JWT Signature : 403 : SignatureException
 * 4. Token expired : ExpiredJwtException
 */
@RestControllerAdvice // if dispacher servlet received the request than only it will throw the exception
public class CustomExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ProblemDetail handleSecurityException(Exception exception) {
        ProblemDetail errorDetails = null;

        //Bad Credential : Authentication Failure : 401
        if (exception instanceof BadCredentialsException) {
            errorDetails = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(401), exception.getMessage());
            errorDetails.setProperty("access_denied_reason","Authentication Failure");
        }

        //Access denied : Authorization ERROR : 403
        if(exception instanceof AccessDeniedException){
            errorDetails = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(403), exception.getMessage());
            errorDetails.setProperty("access_denied_reason","Not Authorized");
        }

        /**Below two is handles before the dispacher servlet spring security filter or Authorization filter*/
        //Invalid JWT Signature : 403 : SignatureException
        if(exception instanceof SignatureException){
            errorDetails = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(403), exception.getMessage());
            errorDetails.setProperty("access_denied_reason","Invalid Jwt Token or Signature modified");
        }

        //Token expired : ExpiredJwtException
        if(exception instanceof ExpiredJwtException){
            errorDetails = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(403), exception.getMessage());
            errorDetails.setProperty("access_denied_reason","Token already Expired");
        }

        return errorDetails;
    }
}
