package com.example.security.Entity;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ReportRepository extends JpaRepository<Report, Long> {
    Report findByReportId(long id);
    List<Report> findByReportTypeAndUsername(String rType, String username);     // 타입과 이름으로 찾기
    List<Report> findByUsernameStartsWithOrderByWriteDateDesc(String username);  // 이름 일부로 찾기 - admin
    List<Report> findByReportTitleContainingOrderByWriteDateDesc(String title);  // 제목을 포함해서 찾기 - admin
    List<Report> findAllByOrderByUpdatedTimeDesc();                              // 업데이트 날짜 내림차순으로 찾기
    List<Report> findByReportTypeOrderByWriteDateDesc(String type);              // 타입으로 찾기 - admin
    List<Report> findByStateOrderByWriteDateDesc(String state);                  // 스테이트로 찾기 - admin
    List<Report> findByUsernameOrderByUpdatedTime(String username);              // 이름으로 찾기
    List<Report> findByUsernameAndReportTitleContainingOrderByWriteDate(String username, String title); // 이름과 제목으로 찾기 - user
    List<Report> findByUsernameAndReportTypeOrderByWriteDateDesc(String username, String type);         // 이름과 타입으로 찾기 - user
    List<Report> findByUsernameAndStateOrderByWriteDateDesc(String username, String state);             // 이름과 스테이트로 찾기 - user
}
