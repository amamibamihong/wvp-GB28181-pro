package com.genersoft.iot.vmp.gb35114.sip;

/**
 * GB35114 信令/密码层校验失败时抛出的运行时异常，线格式或验签错误都可携带。
 */
public class Gb35114Exception extends RuntimeException {

    public Gb35114Exception(String message) {
        super(message);
    }

    public Gb35114Exception(String message, Throwable cause) {
        super(message, cause);
    }
}
