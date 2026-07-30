package com.estudos.springsecurity.entity;

public record RegisterDTO(String login, String password, UserRole role) {
}
