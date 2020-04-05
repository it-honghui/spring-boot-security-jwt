package cn.gathub;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit4.SpringRunner;

import javax.annotation.Resource;

@RunWith(SpringRunner.class)
@SpringBootTest
public class PasswordTest {

    @Resource
    PasswordEncoder passwordEncoder;

    @Test
    public void contextLoads() {
        System.out.println(passwordEncoder.encode("123456"));
    }


}
