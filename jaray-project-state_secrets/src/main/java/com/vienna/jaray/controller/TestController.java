package com.vienna.jaray.controller;

import com.vienna.jaray.model.RequestModel;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

@Slf4j
@CrossOrigin("*")
@RestController
public class TestController {

    @PostMapping("/test")
    public Object test(@RequestBody RequestModel model){
        log.info("test 请求明文：{}", model);
        return model;
    }


    @GetMapping("/test1")
    public Object test1(RequestModel model){
        log.info("test2 请求明文：{}", model);
        return model;
    }



    @PostMapping("/nationalSecrets/test")
    public Object nationalSecretsTest(@RequestBody RequestModel model){
        log.info("nationalSecrets test 请求明文：{}", model);
        return model;
    }


    @GetMapping("/nationalSecrets/test1")
    public Object nationalSecretsTest1(RequestModel model){
        log.info("nationalSecrets test2 请求明文：{}", model);
        return model;
    }
}
