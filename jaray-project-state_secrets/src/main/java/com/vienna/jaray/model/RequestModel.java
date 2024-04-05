package com.vienna.jaray.model;

import lombok.Data;

@Data
public class RequestModel {
    /**
     * 用户名
     */
    private String userName;
    /**
     * 年龄
     */
    private int age;
    /**
     * 性别
     */
    private String gender;
}
