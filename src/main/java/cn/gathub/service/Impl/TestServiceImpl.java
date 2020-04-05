package cn.gathub.service.Impl;

import cn.gathub.entity.PersonDemo;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

import static org.springframework.security.core.context.SecurityContextHolder.getContext;

@Service
public class TestServiceImpl {

    /**
     * 注解适合进入方法前的权限验证。只有拥有ADMIN角色才能访问findAll方法。如果当前登录用户没有PreAuthorize需要的权限，将抛出org.springframework.security.access.AccessDeniedException异常！
     */
    @PreAuthorize("hasRole('admin')")
    public List<PersonDemo> findAll() {
        return null;
    }

    /**
     * 在方法执行后再进行权限验证,适合根据返回值结果进行权限验证。Spring EL 提供返回对象能够在表达式语言中获取返回的对象returnObject。下文代码只有返回值的name等于authentication对象的name（当前登录用户名）才能正确返回，否则抛出异常。
     */
    @PostAuthorize("returnObject.name == authentication.name")
    public PersonDemo findOne() {
        String authName =
                getContext().getAuthentication().getName();
        System.out.println(authName);
        return new PersonDemo("admin");
    }

    /**
     * 针对参数进行过滤,下文代码表示针对ids参数进行过滤，只有id为偶数的元素才被作为参数传入函数。
     */
    @PreFilter(filterTarget = "ids", value = "filterObject%2==0")
    public void delete(List<Integer> ids, List<String> usernames) {
        System.out.println();
    }

    /**
     * 针对返回结果进行过滤，特别适用于集合类返回值，过滤集合中不符合表达式的对象。如果使用admin登录系统，上面的函数返回值list中test将被过滤掉，只剩下admin。
     */
    @PostFilter("filterObject.name == authentication.name")
    public List<PersonDemo> findAllPD() {

        List<PersonDemo> list = new ArrayList<>();
        list.add(new PersonDemo("test"));
        list.add(new PersonDemo("admin"));

        return list;
    }

}
