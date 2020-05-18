package com.example.security.Controller;

import com.example.security.Dao.ReportDao;
import com.example.security.Entity.Report;
import com.example.security.Entity.ReportRepository;
import com.example.security.Entity.Task;
import com.example.security.Entity.TaskRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.mail.MessagingException;
import javax.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

@Slf4j
@Controller
@RequestMapping("/report")
public class ReportController {
    @Autowired
    ReportRepository reportRepository;

    @Autowired
    ReportDao rd;

    @Autowired
    TaskRepository taskRepository;

    public int LoginOrNot(Authentication authentication) {
        log.info("auth : " + authentication);
        if(authentication == null)  return -1;
        else return 1;
    }

    @GetMapping // report 전체보기
    public String reportList(Model model, Authentication auth) {
        int loginOrNot = LoginOrNot(auth);
        if(loginOrNot == -1) return "redirect:/";

        List<Report> list;
        //System.out.println(auth.getName() + " in report list");
        Map<String, String> authority = rd.getUserInfo(auth.getName());
        String role = authority.get("role");
        if(role.equals("USER")) {
            list = reportRepository.findByUsernameOrderByUpdatedTime(auth.getName());
            List<Report> noticeList = reportRepository.findByReportTypeOrderByWriteDateDesc("Notice");
            list.addAll(noticeList);
        } else {
            list = reportRepository.findAllByOrderByUpdatedTimeDesc();
        }
        model.addAttribute("list",list);
        model.addAttribute("authority", authority);

        return "report/report_list";
    }

    @GetMapping("/search") // report 검색해서 보기
    public String reportSearch(Authentication auth, Model model, HttpServletRequest request) {
        int loginOrNot = LoginOrNot(auth);
        if(loginOrNot == -1) return "redirect:/";

        Map<String, String> authority = rd.getUserInfo(auth.getName());
        model.addAttribute("authority", authority);

        String type = request.getParameter("search1");
        String finding = request.getParameter("searching2");
        log.info(type + " " + finding);
        List<Report> rlist = new ArrayList<>();

        if(authority.get("role").equals("USER")) { // User인 경우
            switch (type) {
                case "username":
                    rlist = reportRepository.findByUsernameStartsWithOrderByWriteDateDesc(finding);
                    break;
                case "reportTitle":
                    rlist = reportRepository.findByUsernameAndReportTitleContainingOrderByWriteDate(auth.getName(), finding);
                    break;
                case "time":
                    List<Report> rl = reportRepository.findByUsernameOrderByUpdatedTime(auth.getName());
                    for(Report r : rl) {
                        if(finding.equals(r.getWriteDate().toLocalDate().toString()))
                            rlist.add(r);
                    }
                    break;
                case "type":
                    rlist = reportRepository.findByUsernameAndReportTypeOrderByWriteDateDesc(auth.getName(), finding);
                    break;
                case "state":
                    rlist = reportRepository.findByUsernameAndStateOrderByWriteDateDesc(auth.getName(), finding);
                    break;
            }
        } else { // Admin인 경우
            switch (type) {
                case "username":
                    rlist = reportRepository.findByUsernameStartsWithOrderByWriteDateDesc(finding);
                    break;
                case "reportTitle":
                    rlist = reportRepository.findByReportTitleContainingOrderByWriteDateDesc(finding);
                    break;
                case "time":
                    List<Report> rl = reportRepository.findAllByOrderByUpdatedTimeDesc();
                    for (Report rp : rl) {
                        if (finding.equals(rp.getWriteDate().toLocalDate().toString())) {
                            rlist.add(rp);
                        }
                    }
                    break;
                case "type":
                    rlist = reportRepository.findByReportTypeOrderByWriteDateDesc(finding);
                    break;
                case "state":
                    rlist = reportRepository.findByStateOrderByWriteDateDesc(finding);
                    break;
            }
        }

        model.addAttribute("list",rlist);
        return "report/report_list";
    }

//    @GetMapping("/sorting") // report 정렬해서 원하는 것 보기
//    public String reportSorting(Authentication auth, Model model, @RequestParam("Big")String big,
//                                @RequestParam("Small")String small) {
//        Map<String, String> authority = rd.getUserInfo(auth.getName());
//        model.addAttribute("authority", authority);
//
//        System.out.println(big + " , " + small);
//        List<Report> rlist = null;
//        if(big.equals("type")) {
//            rlist = reportRepository.findByReportTypeOrderByWriteDateDesc(small);
//        } else if(big.equals("state")) {
//            rlist = reportRepository.findByStateOrderByWriteDateDesc(small);
//        }
//        model.addAttribute("list",rlist);
//
//        return "report/report_list";
//    }

    @GetMapping("/detail/{reportId}") // report 상세보기
    public String reportView(@PathVariable("reportId") long reportid, Model model, Authentication auth,
                             HttpServletRequest request) {
        int loginOrNot = LoginOrNot(auth);
        if(loginOrNot == -1) return "redirect:/";

        Map<String, String> authority = rd.getUserInfo(auth.getName());
        model.addAttribute("authority",authority);

        List<Task> list = this.taskRepository.findByReportId(reportid);
        System.out.println(list);
        model.addAttribute("list",list);

        Report rp = this.reportRepository.findByReportId(reportid);
        model.addAttribute("info",rp);
        model.addAttribute("oldUrl", request.getHeader("referer"));

        return "report/report_detail";
    }

    @GetMapping("/create/daily")
    public String createDaily(Model model, Authentication auth, HttpServletRequest request) {
        int loginOrNot = LoginOrNot(auth);
        if(loginOrNot == -1) return "redirect:/";

        Map<String, String> authority = rd.getUserInfo(auth.getName());
        model.addAttribute("authority", authority);

        List<Map<String, Object>> list = new ArrayList<>();
        model.addAttribute("task", list);
        model.addAttribute("oldUrl", request.getHeader("referer"));

        return "report/create_daily";
    }

    @PostMapping("/create/daily")
    public String createDailyAction(Authentication auth, HttpServletRequest request) {
        Enumeration<String> keys = request.getParameterNames();

        LocalDateTime now = LocalDateTime.now();
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyyMMdd");
        String nowDate = now.format(dtf);

        //Report Save
        Report report = new Report();
        report.setUsername(auth.getName());
        report.setReportType("Daily");
        report.setSimpleDate(nowDate);
        report.setWriteDate(now);
        report.setUpdatedTime(now);
        report.setState("Waiting");
        report.setReportTitle(nowDate + "_Daily_Report");
        System.out.println(report);
        reportRepository.save(report);

        System.out.println(report.getReportId());
        long r_id = report.getReportId();

        //Task Save
        while (keys.hasMoreElements()) {
            String key = keys.nextElement();
            log.info(key + ": " + request.getParameter(key));
            Task task = new Task();
            task.setReportId(r_id);
            task.setUsername(auth.getName());
            task.setSimpleDate(nowDate);
            task.setReportType("Daily");
            task.setReportKind("Done");
            //
            System.out.println(request.getParameter(key).length());
            String donedone = request.getParameter(key);
            if(request.getParameter(key).length() >= 2000) {
                donedone = donedone.substring(0,1999);
            }
            task.setDone(donedone);
            //
            System.out.println(task);
            taskRepository.save(task);
        }

        return "redirect:/report";
    }

    @GetMapping("/create/weekly")
    public String createWeekly(Authentication auth, Model model, HttpServletRequest request) {
        int loginOrNot = LoginOrNot(auth);
        if(loginOrNot == -1) return "redirect:/";

        Map<String, String> authority = rd.getUserInfo(auth.getName());
        model.addAttribute("authority", authority);

        List<Report> rlist = reportRepository.findByReportTypeAndUsername("Weekly",auth.getName());
        long idx = -1;
        boolean isNull = true; // 아무 것도 없으면 처음 주간 리포트 쓰는 경우
        if(rlist.size() != 0) {
            idx = rlist.get(rlist.size()-1).getReportId();
            isNull = false; // 있다면 주간 리포트를 한 번 이상 쓴 경우
        }
        List<Task> tlist = null;
        if(idx != -1) tlist = taskRepository.findByReportId(idx);
        model.addAttribute("task", tlist);
        model.addAttribute("Valid", isNull);
        model.addAttribute("oldUrl", request.getHeader("referer"));

        return "report/create_weekly";
    }

    @PostMapping("/create/weekly")
    public String createWeeklyAction(Authentication auth, HttpServletRequest request) {
        Enumeration<String> keys = request.getParameterNames();

        LocalDateTime now = LocalDateTime.now();
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyyMMdd");
        String nowDate = now.format(dtf);

        //Report Save
        Report report = new Report();
        report.setUsername(auth.getName());
        report.setReportType("Weekly");
        report.setSimpleDate(nowDate);
        report.setWriteDate(now);
        report.setUpdatedTime(now);
        report.setState("Waiting");
        report.setReportTitle(nowDate + "_Weekly_Report");
        System.out.println(report);
        reportRepository.save(report);

        System.out.println(report.getReportId());
        long r_id = report.getReportId();

        while(keys.hasMoreElements()) {
            String key = keys.nextElement();
            int loc1 = key.indexOf("done");
            int loc2 = key.indexOf("plan");
            log.info(key + " : " + request.getParameter(key) + " -- loc1 : " + loc1 + ", loc2 : " + loc2);
            Task task = new Task();
            task.setReportId(r_id);
            task.setUsername(auth.getName());
            task.setSimpleDate(nowDate);
            task.setReportType("Weekly");
            if(loc1 == 0) {
                task.setReportKind("weekly_result");
                task.setDone(request.getParameter(key));
                key = keys.nextElement();
                task.setRealAchievement(request.getParameter(key));
            } else if(loc2 == 0) {
                task.setReportKind("weekly_plan");
                task.setProgress(request.getParameter(key));
                key = keys.nextElement();
                task.setExpectedAchievement(request.getParameter(key));
            }
            key = keys.nextElement();
            //
            System.out.println(request.getParameter(key).length());
            String commentcommment = request.getParameter(key);
            if(commentcommment.length() >= 2000)
                commentcommment =  commentcommment.substring(0,1999);
            task.setComment(commentcommment);
            //
            System.out.println(task);
            taskRepository.save(task);
        }

        return "redirect:/report";
    }

    @GetMapping("/create/monthly")
    public String createMonthly(Authentication auth, Model model, HttpServletRequest request) {
        int loginOrNot = LoginOrNot(auth);
        if(loginOrNot == -1) return "redirect:/";

        Map<String, String> authority = rd.getUserInfo(auth.getName());
        model.addAttribute("authority", authority);

        List<Report> rlist = reportRepository.findByReportTypeAndUsername("Monthly", auth.getName());
        System.out.println(rlist);
        long idx = -1;
        boolean isNull = true;
        if(rlist.size() != 0) {
            idx = rlist.get(rlist.size()-1).getReportId();
            isNull = false;
        }

        List<Task> tlist = new ArrayList<>();
        if(idx != -1) tlist = taskRepository.findByReportId(idx);
        model.addAttribute("task",tlist);
        model.addAttribute("boolValue",isNull);
        model.addAttribute("oldUrl", request.getHeader("referer"));

        return "report/create_monthly";
    }

    @PostMapping("/create/monthly")
    public String createMonthlyAction(Authentication auth, HttpServletRequest request) {
        Enumeration<String> keys = request.getParameterNames();

        LocalDateTime now = LocalDateTime.now();
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyyMMdd");
        String nowDate = now.format(dtf);

        //Report Save
        Report report = new Report();
        report.setUsername(auth.getName());
        report.setReportType("Monthly");
        report.setSimpleDate(nowDate);
        report.setWriteDate(now);
        report.setUpdatedTime(now);
        report.setState("Waiting");
        report.setReportTitle(nowDate + "_Monthly_Report");
        System.out.println(report);
        reportRepository.save(report);

        System.out.println(report.getReportId());
        long r_id = report.getReportId();

        while(keys.hasMoreElements()) {
            String key = keys.nextElement();
            int loc1 = key.indexOf("done");
            int loc2 = key.indexOf("plan");
            log.info(key + " : " + request.getParameter(key) + " -- loc1 : " + loc1 + ", loc2 : " + loc2);
            Task task = new Task();
            task.setReportId(r_id);
            task.setUsername(auth.getName());
            task.setSimpleDate(nowDate);
            task.setReportType("Monthly");
            if(loc1 == 0) {
                task.setReportKind("Done");
                task.setDone(request.getParameter(key));
                key = keys.nextElement();
                task.setRealAchievement(request.getParameter(key));
                key = keys.nextElement();
                task.setProjectStartDate(request.getParameter(key));
                key = keys.nextElement();
                task.setProjectTargetDate(request.getParameter(key));
                key = keys.nextElement();
                task.setProgress(request.getParameter(key));
                key = keys.nextElement();
                //
                String commentComment = request.getParameter(key);
                if(commentComment.length() >= 2000) commentComment = commentComment.substring(0,1999);
                //
                task.setComment(commentComment);
                key = keys.nextElement();
                task.setQuarter1(request.getParameter(key));
                key = keys.nextElement();
                task.setQuarter2(request.getParameter(key));
                key = keys.nextElement();
                task.setQuarter3(request.getParameter(key));
                key = keys.nextElement();
                task.setQuarter4(request.getParameter(key));
            } else if(loc2 == 0) {
                task.setReportKind("Next_Month_plan");
                task.setProgress(request.getParameter(key));
                key = keys.nextElement();
                task.setExpectedAchievement(request.getParameter(key));
                key = keys.nextElement();
                //
                String commentComment = request.getParameter(key);
                if(commentComment.length() >= 2000) commentComment = commentComment.substring(0,1999);
                //
                task.setComment(commentComment);
            }
            System.out.println(task);
            taskRepository.save(task);
        }

        return "redirect:/report";
    }

    @GetMapping("/create/project_goal")
    public String createProjectGoal(Authentication auth, Model model, HttpServletRequest request) {
        int loginOrNot = LoginOrNot(auth);
        if(loginOrNot == -1) return "redirect:/";

        Map<String, String> authority = rd.getUserInfo(auth.getName());
        model.addAttribute("authority", authority);

        List<Task> tlist = new ArrayList<>();
        model.addAttribute("task",tlist);
        model.addAttribute("oldUrl", request.getHeader("referer"));

        return "report/create_yearly";
    }

    @PostMapping("/create/project_goal")
    public String createProjectGoalAction(Authentication auth, HttpServletRequest request) {
        Enumeration<String> keys = request.getParameterNames();

        LocalDateTime now = LocalDateTime.now();
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyyMMdd");
        String nowDate = now.format(dtf);

        //Report Save
        Report report = new Report();
        report.setUsername(auth.getName());
        report.setReportType("Yearly");
        report.setSimpleDate(nowDate);
        report.setWriteDate(now);
        report.setUpdatedTime(now);
        report.setState("Waiting");
        report.setReportTitle(nowDate + "_Yearly_Report");
        System.out.println(report);
        reportRepository.save(report);

        System.out.println(report.getReportId());
        long r_id = report.getReportId();

        while(keys.hasMoreElements()) {
            String key = keys.nextElement();
            log.info(key + " : " + request.getParameter(key));
            Task task = new Task();
            task.setReportId(r_id);
            task.setUsername(auth.getName());
            task.setSimpleDate(nowDate);
            task.setReportType("Yearly");
            task.setReportKind("project_goal");
            task.setProgress(request.getParameter(key));
            key = keys.nextElement();
            //
            String commentCommment = request.getParameter(key);
            if(commentCommment.length() >= 2000)
                commentCommment =  commentCommment.substring(0,1999);
            task.setComment(commentCommment);
            //
            key = keys.nextElement();
            task.setProjectStartDate(request.getParameter(key));
            key = keys.nextElement();
            task.setProjectTargetDate(request.getParameter(key));
            key = keys.nextElement();
            task.setQuarter1(request.getParameter(key));
            key = keys.nextElement();
            task.setQuarter2(request.getParameter(key));
            key = keys.nextElement();
            task.setQuarter3(request.getParameter(key));
            key = keys.nextElement();
            task.setQuarter4(request.getParameter(key));

            System.out.println(task);
            taskRepository.save(task);
        }

        return "redirect:/report";
    }

    @GetMapping("/create/notice")
    public String createNotice(Authentication auth, Model model, HttpServletRequest request) {
        int loginOrNot = LoginOrNot(auth);
        if(loginOrNot == -1) return "redirect:/";

        Map<String, String> authority = rd.getUserInfo(auth.getName());
        model.addAttribute("authority", authority);

        List<Task> taskList = new ArrayList<>();
        model.addAttribute("task", taskList);
        model.addAttribute("oldUrl", request.getHeader("referer"));

        return "/report/create_notice";
    }

    @PostMapping("/create/notice")
    public String createNoticeAction(Authentication auth, HttpServletRequest request) {
        Enumeration<String> keys = request.getParameterNames();

        LocalDateTime now = LocalDateTime.now();
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyyMMdd");
        String nowDate = now.format(dtf);

        //Report Save
        Report report = new Report();
        report.setUsername(auth.getName());
        report.setReportType("Notice");
        report.setSimpleDate(nowDate);
        report.setWriteDate(now);
        report.setUpdatedTime(now);
        report.setState("Approved");
        report.setReportTitle(nowDate + "_Notice");
        System.out.println(report);
        reportRepository.save(report);

        System.out.println(report.getReportId());
        long r_id = report.getReportId();

        while(keys.hasMoreElements()) {
            String key = keys.nextElement();
            log.info(key + " : " + request.getParameter(key));
            Task task = new Task();
            task.setReportId(r_id);
            task.setUsername(auth.getName());
            task.setSimpleDate(nowDate);
            task.setReportType("Notice");
            task.setReportKind("notice");
            task.setProgress(request.getParameter(key));
            System.out.println(task);
            taskRepository.save(task);
        }

        return "redirect:/report";
    }

    @PostMapping("/change_state")
    public String changeState(HttpServletRequest request) throws MessagingException {
        Enumeration<String> line = request.getParameterNames();
        long id = -1;
        while(line.hasMoreElements()){
            String tmp = line.nextElement();
            log.info(tmp + " _ " + request.getParameter(tmp));
            if(tmp.equals("report_id"))
                id = Long.parseLong(request.getParameter(tmp));
            else if(tmp.equals("Approve")) {
                Report report = reportRepository.findByReportId(id);
                EmailSendController es = new EmailSendController();
                System.out.println("Username : " + report.getUsername());
                es.SendApproveOrReject(report.getUsername(), "Approved");
                report.setState("Approved");
                reportRepository.save(report);
            }
            else if(tmp.equals("Reject")) {
                Report report = reportRepository.findByReportId(id);
                report.setState("Rejected");
                reportRepository.save(report);
            }
        }

        return "redirect:/report/detail/" + id;
    }

    @GetMapping("/request_state")
    public String reviewReport(@RequestParam("rId")String id, @RequestParam("username")String name) throws MessagingException {
        Report rp = reportRepository.findByReportId(Long.parseLong(id));
        rp.setState("Requested");
        reportRepository.save(rp);

        return "redirect:/report/detail/" + id;
    }

    @PostMapping("/delete")
    public String deleteReport(@RequestParam("reportID")String id) {
        long r_id = Long.parseLong(id);
        List<Task> tlist = taskRepository.findByReportId(r_id);
        for(Task t : tlist) {
            taskRepository.delete(t);
        }
        Report r = reportRepository.findByReportId(r_id);
        reportRepository.delete(r);

        return "redirect:/report";
    }
}
