package com.demo.modules.account.domain;

import com.demo.modules.account.application.request.AccountUpdateRequest;
import com.demo.modules.common.type.Role;
import com.demo.modules.common.domain.BaseEntity;
import com.demo.modules.education.domain.Education;
import com.demo.modules.organization.domain.Organization;
import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.sun.istack.NotNull;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.oauth2.core.user.OAuth2User;

import javax.persistence.*;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

@Entity
@Getter
@Setter
@NoArgsConstructor
public class Account extends BaseEntity {

    @Id
    @GeneratedValue
    private Long id;

    private String name;

    @JsonIgnore
    private String password;
    @NotNull
    @Column(unique = true)
    private String email;
    private String age;
    private String location;

    private boolean isEmailVerified;
    private String profileImage;

    @Enumerated(EnumType.STRING)
    private Role role;

    @ManyToMany(mappedBy = "accounts")
    @JsonBackReference
    private Set<Education> educations = new HashSet<>();

    @ManyToOne
    private Organization organization;

    @JsonIgnore
    @OneToOne(mappedBy = "director", fetch = FetchType.LAZY)
    private Organization director;

    public Account(String name, String email, String picture) {
        this.name = name;
        this.email = email;
        this.profileImage = picture;
        this.role = Role.USER;
    }

    public void setUpdateData(AccountUpdateRequest account) {
        this.name = account.getName();
        this.email = account.getEmail();
        this.age = account.getAge();
        this.location = account.getLocation();
    }

    public Account update(String name, String picture) {
        this.name = name;
        this.profileImage = picture;
        if (Objects.isNull(this.role)) {
            this.role = Role.USER;
        }

        return this;
    }

    public Account toAccount(OAuth2User oAuth2User) {
        Map<String, Object> attributes = oAuth2User.getAttributes();
        return new Account(
            (String) attributes.get("name"),
            (String) attributes.get("email"),
            (String) attributes.get("picture"));
    }
}
