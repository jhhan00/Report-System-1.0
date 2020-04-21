package com.example.security.Entity;

import lombok.Data;

import javax.persistence.*;

@Data
@Entity
@Table(name="taskTable")
public class Task {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long idx;

    private Long reportId;
    private String username;
    private String simpleDate;
    private String reportType;
    private String reportKind;

    @Column(length = 6000)
    private String progress;

    @Column(length = 6000)
    private String done;

    private String expectedAchievement;
    private String realAchievement;

    @Column(length = 6000)
    private String comment;
}
