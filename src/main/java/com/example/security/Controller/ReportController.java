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

    @GetMapping // report 전체보기
    public String reportList(Model model, Authentication auth) {
        List<Report> list = reportRepository.findAllByOrderByUpdatedTimeDesc();
        model.addAttribute("list",list);

        //System.out.println(auth.getName() + " in report list");
        Map<String, String> authority = rd.getUserInfo(auth.getName());
        model.addAttribute("authority", authority);

        return "report/report_list";
    }

    @GetMapping("/search") // report 검색해서 보기
    public String reportSearch(Authentication auth, Model model, @RequestParam("type")String type,
                               @RequestParam("search")String info) {
        Map<String, String> authority = rd.getUserInfo(auth.getName());
        model.addAttribute("authority", authority);

        List<Report> rlist = new ArrayList<>();
        if(type.equals("username")) {
            rlist = reportRepository.findByUsernameStartsWithOrderByWriteDateDesc(info);
        } else if(type.equals("reportTitle")) {
            rlist = reportRepository.findByReportTitleContainingOrderByWriteDateDesc(info);
        } else if(type.equals("time")) {
            log.info("Input Time : " + info);
            List<Report> rl = reportRepository.findAllByOrderByUpdatedTimeDesc();
            for(Report rp : rl) {
                if(info.equals(rp.getWriteDate().toLocalDate().toString())) {
                    log.info(rp.toString());
                    rlist.add(rp);
                }
            }
        }
        model.addAttribute("list",rlist);
        return "report/report_list";
    }

    @GetMapping("/sorting") // report 정렬해서 원하는 것 보기
    public String reportSorting(Authentication auth, Model model, @RequestParam("Big")String big,
                                @RequestParam("Small")String small) {
        Map<String, String> authority = rd.getUserInfo(auth.getName());
        model.addAttribute("authority", authority);

        System.out.println(big + " , " + small);
        List<Report> rlist = null;
        if(big.equals("type")) {
            rlist = reportRepository.findByReportTypeOrderByWriteDateDesc(small);
        } else if(big.equals("state")) {
            rlist = reportRepository.findByStateOrderByWriteDateDesc(small);
        }
        model.addAttribute("list",rlist);

        return "report/report_list";
    }

    @GetMapping("/detail/{reportId}") // report 상세보기
    public String reportView(@PathVariable("reportId") long reportid, Model model, Authentication auth) {
        //System.out.println(reportid + ". " + auth.getName() + " in detail");

        Map<String, String> authority = rd.getUserInfo(auth.getName());
        model.addAttribute("authority",authority);

        List<Task> list = this.taskRepository.findByReportId(reportid);
        model.addAttribute("list",list);

        Report rp = this.reportRepository.findByReportId(reportid);
        model.addAttribute("info",rp);

        return "report/report_detail";
    }

    @GetMapping("/create/daily")
    public String createDaily(Model model, Authentication auth) {
        Map<String, String> authority = rd.getUserInfo(auth.getName());
        model.addAttribute("authority", authority);

        List<Map<String, Object>> list = null;
        model.addAttribute("task",list);

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
            if(request.getParameter(key).length() >= 6000) {
                donedone = donedone.substring(0,6000);
            }
            task.setDone(donedone);
            //
            System.out.println(task);
            taskRepository.save(task);
        }

        return "redirect:/report";
    }

    @GetMapping("/create/weekly")
    public String createWeekly(Authentication auth, Model model) {
        Map<String, String> authority = rd.getUserInfo(auth.getName());
        model.addAttribute("authority", authority);

        List<Report> rlist = reportRepository.findByReportTypeAndUsername("Weekly",auth.getName());
        long idx = -1;
        if(rlist.size() != 0){
//            System.out.println(rlist);
//            System.out.println(rlist.get(0).getReportId());
//            System.out.println(rlist.get(rlist.size()-1).getReportId());
            idx = rlist.get(rlist.size()-1).getReportId();
        }
        List<Task> tlist = null;
        if(idx != -1) tlist = taskRepository.findByReportId(idx);
        model.addAttribute("task", tlist);

        boolean isValid = false;
        System.out.println("idx : " + idx);
//        if(tlist != null)System.out.println(tlist.get(tlist.size()-1));
        if(tlist != null && tlist.get(tlist.size()-1).getReportKind().equals("weekly_plan")) isValid=true;
        System.out.println("isValid : " + isValid);
        model.addAttribute("Valid",isValid);

        return "report/create_weekly";
    }

    @PostMapping("/create/weekly")
    public String createWeeklyAction(Authentication auth, HttpServletRequest request) {
        Enumeration<String> keys = request.getParameterNames();
        String line = keys.nextElement();
        String temp = "";
        if(request.getParameter(line).equals("plan"))
            temp = "weekly_plan";
        else if(request.getParameter(line).equals("after"))
            temp = "weekly_result";

        List<Report> rlist = reportRepository.findByReportTypeAndUsername("Weekly",auth.getName());
        long idx = -1;
        if(rlist.size() != 0) idx = rlist.get(rlist.size()-1).getReportId();
        System.out.println("idx = " + idx);

        LocalDateTime now = LocalDateTime.now();
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyyMMdd");
        String nowDate = now.format(dtf);

        //Report Save
        Report report;
        if(temp.equals("weekly_plan")){
            report = new Report();
            report.setUsername(auth.getName());
            report.setReportType("Weekly");
            report.setSimpleDate(nowDate);
            report.setWriteDate(now);
            report.setUpdatedTime(now);
            report.setState("Waiting");
            report.setReportTitle(nowDate + "_Weekly_Report");
            System.out.println(report);
        } else {
            report = reportRepository.findByReportId(idx);
            report.setUpdatedTime(now);
            report.setState("Waiting");
            report.setReportTitle(nowDate + "_Weekly_Report");
            System.out.println(report);
        }
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
            task.setReportType("Weekly");
            task.setReportKind(temp);
            if(temp.equals("weekly_plan")) { // Weekly Report의 시작인 경우
                task.setProgress(request.getParameter(key));
                key = keys.nextElement();
                task.setExpectedAchievement(request.getParameter(key));
            } else { // Weekly Report의 끝인 경우
                task.setDone(request.getParameter(key));
                Task t1 = taskRepository.findByReportIdAndProgress(r_id,task.getDone());
                System.out.println("t1 : " + t1);
                if(t1 != null) {
                    System.out.println("Right Now ExpectedAchievement : " + t1.getExpectedAchievement());
                    task.setExpectedAchievement(t1.getExpectedAchievement());
                }
                key = keys.nextElement();
                task.setRealAchievement(request.getParameter(key));
            }
            key = keys.nextElement();
            //
            System.out.println(request.getParameter(key).length());
            String commentcommment = request.getParameter(key);
            if(commentcommment.length() >= 6000)
                commentcommment =  commentcommment.substring(0,6000);
            task.setComment(commentcommment);
            //
            System.out.println(task);
            taskRepository.save(task);
        }

        return "redirect:/report";
    }

    @GetMapping("/create/monthly")
    public String createMonthly(Authentication auth, Model model) {
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

        List<Task> tlist = null;
        if(idx != -1) tlist = taskRepository.findByReportId(idx);
        model.addAttribute("task",tlist);
        model.addAttribute("boolValue",isNull);

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
            } else if(loc2 == 0) {
                task.setReportKind("Next_Month_plan");
                task.setProgress(request.getParameter(key));
                key = keys.nextElement();
                task.setExpectedAchievement(request.getParameter(key));
            }
            key = keys.nextElement();
            //
            System.out.println(request.getParameter(key).length());
            String commentcommment = request.getParameter(key);
            if(commentcommment.length() >= 6000)
                commentcommment =  commentcommment.substring(0,6000);
            task.setComment(commentcommment);
            //
            System.out.println(task);
            taskRepository.save(task);
        }

        return "redirect:/report";
    }

    @GetMapping("/create/project_goal")
    public String createProjectGoal(Authentication auth, Model model) {
        Map<String, String> authority = rd.getUserInfo(auth.getName());
        model.addAttribute("authority", authority);

        List<Task> tlist = null;
        model.addAttribute("task",tlist);

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
            int loc1 = key.indexOf("project");
            int loc2 = key.indexOf("milestone");
            task.setReportId(r_id);
            task.setUsername(auth.getName());
            task.setSimpleDate(nowDate);
            task.setReportType("Yearly");
            if(loc1==0) {
                task.setReportKind("project_description");
            } else if(loc2==0) {
                task.setReportKind("milestone");
            }
            task.setProgress(request.getParameter(key));
            key = keys.nextElement();
            //
            System.out.println(request.getParameter(key).length());
            String commentcommment = request.getParameter(key);
            if(commentcommment.length() >= 6000)
                commentcommment =  commentcommment.substring(0,6000);
            task.setComment(commentcommment);
            //
            System.out.println(task);
            taskRepository.save(task);
        }

        return "redirect:/report";
    }

    @GetMapping("/create/notice")
    public String createNotice(Authentication auth, Model model) {
        Map<String, String> authority = rd.getUserInfo(auth.getName());
        model.addAttribute("authority", authority);

        List<Task> taskList = null;
        model.addAttribute("task",taskList);

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
