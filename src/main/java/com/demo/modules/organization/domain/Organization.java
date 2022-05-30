package com.demo.modules.organization.domain;

import com.demo.modules.account.domain.Account;
import com.demo.modules.common.domain.Address;
import com.demo.modules.common.domain.BaseEntity;
import com.demo.modules.common.type.YN;
import java.time.ZonedDateTime;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

@Entity
@Setter
@Getter
public class Organization extends BaseEntity {

    @Id
    @GeneratedValue
    private Long id;

    private String code;
    private String name;
    @Embedded
    private Address address;
    private int totalMemberCount;
    private int currentMemberCount;

    @OneToMany(mappedBy = "organization")
    @OrderBy("createdAt")
    private List<Account> accounts = new ArrayList<>();

    private YN isOperation;

    @OneToOne(fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    @JoinColumn(name = "account_id")
    private Account director;

    private ZonedDateTime openedAt;
    private YN isOpen;
    private int fixedPeople;
    private int currentPeople;

    public void addAccount(Account account) {
        this.getAccounts().add(account);
    }

    public void addDirector(Account account){
        this.director = account;
    }
}
