package com.demo.modules;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ViewTestController {


    @GetMapping("/index")
    public String login(){
        return "index";
    }
}
