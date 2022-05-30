package com.demo.modules.education.web;

import static com.demo.common.testenv.WithAccountFixture.USERNAME;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.demo.infra.MockMvcTest;
import com.demo.modules.account.web.WithAccount;
import com.demo.modules.education.application.EducationService;
import com.demo.modules.education.domain.Education;
import com.demo.modules.education.infra.EducationRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

@MockMvcTest
class EducationControllerTest {

    @Autowired
    EducationRepository educationRepository;

    @Autowired
    EducationService educationService;

    @Autowired
    MockMvc mockMvc;

    @Autowired
    ObjectMapper objectMapper;

    @BeforeEach
    void beforeEach() {
        Education education = new Education();
        education.setName("과학을 해보자");
        education.setSubject("과학");
        educationRepository.save(education);
    }

    @AfterEach
    void afterEach() {
        educationRepository.deleteAll();
    }

    @DisplayName("교육 전체 조회")
    @Test
    @WithAccount(USERNAME)
    void findEducations() throws Exception {
        mockMvc.perform(get("/api/educations"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].name").isNotEmpty());
    }

    @DisplayName("교육 단건 조회")
    @Test
    @WithAccount(USERNAME)
    void findEducation() throws Exception {
        Education education = educationRepository.findAll().get(0);

        mockMvc.perform(get("/api/educations/{id}", education.getId()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value(education.getName()))
                .andExpect(jsonPath("$.subject").value(education.getSubject()));
    }

    @DisplayName("교육 내용 변경")
    @Test
    @WithAccount(USERNAME)
    void updateEducation() throws Exception {
        Education education = educationRepository.findAll().get(0);

        Map<String, String> map = new HashMap<>();
        map.put("name", "국사를 배우자");
        map.put("subject", "국사");
        mockMvc.perform(put("/api/educations/{id}", education.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(map)))
                .andDo(print())
                .andExpect(status().isOk());

        Education edu = educationRepository.findByName(map.get("name"));
        Education compare = new ModelMapper().map(map, Education.class);
        assertEquals(compare.getName(), edu.getName());
    }

    @DisplayName("교육 삭제")
    @Test
    @WithAccount(USERNAME)
    void deleteEducation() throws Exception {
        Long id = educationRepository.findAll().get(0).getId();
        mockMvc.perform(delete("/api/educations/{id}",  id))
                .andDo(print())
                .andExpect(status().isOk());
    }
}