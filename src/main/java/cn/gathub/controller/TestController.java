package cn.gathub.controller;

import cn.gathub.entity.PersonDemo;
import cn.gathub.service.Impl.TestServiceImpl;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@RestController
public class TestController {

    @Resource
    cn.gathub.service.Impl.TestServiceImpl testService;

    /**
     * 登录
     * formLogin这种方式实现登录认证，不要写这个方法
     */
//    @PostMapping("/login")
//    public String index(String username, String password) {
//        return "index";
//    }

    // 登录成功之后的首页
    @GetMapping("/index")
    public String index() {
        return "index";
    }

    // 日志管理
    @GetMapping("/syslog")
    public String showOrder() {
        return "syslog";
    }

    // 用户管理
    @GetMapping("/sysuser")
    public String addOrder() {
        return "sysuser";
    }

    // 具体业务一
    @GetMapping("/biz1")
    public String updateOrder() {
//        testService.findAll();
//        testService.findOne();
//
//        List<Integer> ids = new ArrayList<>();
//        ids.add(1);
//        ids.add(2);
//        testService.delete(ids, null);
//
//        List<PersonDemo> pds = testService.findAllPD();

        return "biz1";
    }

    // 具体业务二
    @GetMapping("/biz2")
    public String deleteOrder() {
        return "biz2";
    }
}
