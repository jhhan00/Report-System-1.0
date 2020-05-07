package com.example.security.Controller;

import com.example.security.Dao.SimpleUserDao;
import com.example.security.Entity.Report;
import com.example.security.Entity.ReportRepository;
import com.example.security.Extra.GenerateCertNumber;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.Enumeration;

@Slf4j
@Controller
public class EmailSendController {

    @Autowired
    SimpleUserDao sud;
    @Autowired
    JavaMailSender mailSender;
    @Autowired
    ReportRepository reportRepository;

    public void SendApproveOrReject(String name, String state) throws MessagingException {
        MimeMessage message = mailSender.createMimeMessage();
        message.setSubject("Report Result  " + state);
        message.setRecipient(Message.RecipientType.TO, new InternetAddress(name));
        message.setText("Your Report is " + state + ".\nCheck Your Report.");
        message.setSentDate(new Date());
        mailSender.send(message);
    }

    @PostMapping("/change_state")
    public String requestEmailAndChangeState(HttpServletRequest request) throws MessagingException {
        Enumeration<String> line = request.getParameterNames();
        long id = -1;

        while(line.hasMoreElements()){
            String tmp = line.nextElement();
            log.info(tmp + " _ " + request.getParameter(tmp));
            if(tmp.equals("report_id"))
                id = Long.parseLong(request.getParameter(tmp));
            else if(tmp.equals("Approve")) {
                Report report = reportRepository.findByReportId(id);

                MimeMessage message = mailSender.createMimeMessage();
                message.setSubject(report.getReportType() + " Report Result : Approved");
                message.setRecipient(Message.RecipientType.TO, new InternetAddress(report.getUsername()));
                message.setText("Your Report is Approved.\nCheck Your Report.");
                message.setSentDate(new Date());
                mailSender.send(message);

                report.setState("Approved");
                reportRepository.save(report);
            }
            else if(tmp.equals("Reject")) {
                Report report = reportRepository.findByReportId(id);

                MimeMessage message = mailSender.createMimeMessage();
                message.setSubject(report.getReportType() + " Report Result : Rejected");
                message.setRecipient(Message.RecipientType.TO, new InternetAddress(report.getUsername()));
                message.setText("Your Report is Rejected.\nCheck Your Report.");
                message.setSentDate(new Date());
                mailSender.send(message);

                report.setState("Rejected");
                reportRepository.save(report);
            }
        }
        return "redirect:/report/detail/" + id;
    }

    @GetMapping("/request")
    public String SendEmail(@RequestParam("UserId") String id, Model model) throws MessagingException {
        System.out.println(id);
        GenerateCertNumber ge = new GenerateCertNumber();
        String temp = ge.executeGenerate();
        System.out.println(temp);

        MimeMessage message = mailSender.createMimeMessage();
        message.setSubject("회원가입 인증");
        message.setRecipient(Message.RecipientType.TO, new InternetAddress(id));
        message.setText("인증번호는 " + temp + " 입니다.");
        message.setSentDate(new Date());
        mailSender.send(message);

        model.addAttribute("UserId",id);
        model.addAttribute("sendNumber", temp);

        return "signUp/cert";
    }

    @PostMapping("/request_check")
    public String CheckNumber(@RequestParam("check_number") String check, @RequestParam("UserId") String id,
                              @RequestParam("sendNumber")String send, Model model) {
        System.out.println(id);
        System.out.println("sendNumber : "+send);
        System.out.println("check      : "+check);
        String msg = "";
        boolean success = true;
        if(check.equals(send)) {
            System.out.println("Equal Numbers");

            //submit to Database
            try {
                int rst = sud.UpdateEnabled(id);
                if(rst < 1) {
                    msg += "Error in Database..";
                    success = false;
                } else {
                    msg += "Complete!";
                }
            } catch (Exception e) {
                e.printStackTrace();
                msg = "Somthing Wrong... Ask to Administrator";
                success = false;
            }
        } else {
            System.out.println("Error");
            msg += "Try Again...";
            success = false;
        }
        model.addAttribute("msg",msg);
        model.addAttribute("isSuccess",success);
        model.addAttribute("UserId",id);

        return "signUp/cert_result";
    }
}
