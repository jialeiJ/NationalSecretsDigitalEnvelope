package com.vienna.jaray.constant;

import org.springframework.http.HttpStatus;

public enum ErrorCode {

    /**
     * 非法的数据
     */
    ILLEGAL_DATA(505,"非法的数据");

    /**
     * 状态码
     */
    private int statusCode;
    /**
     * 状态描述
     */
    private String statusDesc;

    /**
     *  私有化构造方法
     * @param statusCode 状态码
     * @param statusDesc 状态描述
     */
    private ErrorCode(int statusCode, String statusDesc) {
        this.statusCode = statusCode;
        this.statusDesc = statusDesc;
    }

    /**
     * 获取状态描述方法
     * @param statusCode 状态码
     * @return 状态描述
     */
    public static String getStatusDesc(int statusCode) {
        for (ErrorCode errorCode : ErrorCode.values()) {
            if (errorCode.getStatusCode() == statusCode) {
                return errorCode.statusDesc;
            }
        }
        return null;
    }

    /**
     * 获取状态描述方法
     * @return 状态描述
     */
    public String getStatusDesc() {
        return statusDesc;
    }

    /**
     * 设置状态描述方法
     * @param statusDesc 状态描述
     */
    public void setStatusDesc(String statusDesc) {
        this.statusDesc = statusDesc;
    }

    /**
     * 获取状态码方法
     * @return 状态码
     */
    public int getStatusCode() {
        return statusCode;
    }

    /**
     * 获取状态码方法
     * @return 状态码
     */
    public String getStatusCodeStr() {
        return String.valueOf(statusCode);
    }

    /**
     * 设置状态码方法
     * @param statusCode 状态码
     */
    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }
}
