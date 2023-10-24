package io.github.jokoframework.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.impl.DefaultClaims;

import java.io.Serializable;

public class JokoJWTClaims extends DefaultClaims implements Serializable {

    private static final long serialVersionUID = -8574310592676951264L;
    private JokoJWTExtension joko;

    public JokoJWTClaims(Claims claims, JokoJWTExtension joko) {
        super(claims);
        this.joko = joko;
    }

    public JokoJWTClaims() {

    }

    public JokoJWTClaims(Claims body) {
        this(body, null);
    }

    public JokoJWTExtension getJoko() {
        return joko;
    }

    public JokoJWTClaims setJoko(JokoJWTExtension joko) {
        this.joko = joko;
        return this;
    }

}
