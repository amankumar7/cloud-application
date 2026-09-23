package com.filemanager.CloudApplication.entity;

public enum AuthenticationEventType {

    LOGIN_SUCCESS,
    LOGIN_FAILED,

    LOGOUT,

    REFRESH_SUCCESS,
    REFRESH_FAILED,

    REFRESH_TOKEN_REUSE,

    PASSWORD_CHANGED,

    ACCOUNT_LOCKED,

    REGISTER_SUCCESS, ACCOUNT_UNLOCKED
}