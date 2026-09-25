// test/samples/vulnerable-server.java
// Sample file with intentional Java vulnerabilities for testing Sentinel-VSC

import java.io.*;
import java.sql.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class VulnerableServer extends HttpServlet {

    // ❌ VULNERABLE: Hardcoded credentials (auth-003)
    private static final String DB_PASSWORD = "SuperSecret123!";
    private static final String API_SECRET = "sk-live-XXXXXXXXXXXXXXXX";

    // ❌ VULNERABLE: SQL Injection — Statement with string concatenation (sqli-004)
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String userId = request.getParameter("id");
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/app", "root", DB_PASSWORD);
            Statement stmt = conn.createStatement();
            stmt.executeQuery("SELECT * FROM users WHERE id = '" + userId + "'");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // ❌ VULNERABLE: XSS — unescaped output in servlet response (xss-004)
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String name = request.getParameter("name");
        response.setContentType("text/html");
        response.getWriter().println("<h1>Hello, " + request.getParameter("name") + "</h1>");
    }

    // ❌ VULNERABLE: Path Traversal — File with user input (path-002)
    protected void doDownload(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String filename = request.getParameter("file");
        File file = new File(request.getParameter("file"));
        // Attacker can pass: ../../etc/passwd
        InputStream is = new FileInputStream(file);
        byte[] buffer = new byte[1024];
        int bytesRead;
        while ((bytesRead = is.read(buffer)) != -1) {
            response.getOutputStream().write(buffer, 0, bytesRead);
        }
        is.close();
    }

    // ❌ VULNERABLE: Insecure deserialization — ObjectInputStream (deser-003)
    protected void doDeserialize(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException, ClassNotFoundException {

        ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
        Object obj = ois.readObject();
        response.getWriter().println("Received: " + obj.toString());
    }
}
