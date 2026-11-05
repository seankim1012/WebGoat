package org.owasp.webgoat.demo;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SeededVulnerableController {

  @GetMapping("/demo/user")
  public String user(@RequestParam String name) throws SQLException {
    try (Connection conn = DriverManager.getConnection("jdbc:h2:mem:demo");
        Statement stmt = conn.createStatement()) {
      // SQL injection: user input concatenated into the query
      ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
      return rs.next() ? rs.getString(1) : "none";
    }
  }

  @GetMapping("/demo/ping")
  public String ping(@RequestParam String host) throws IOException {
    // Command injection: user input passed to exec
    Process p = Runtime.getRuntime().exec("ping -c 1 " + host);
    return new String(p.getInputStream().readAllBytes());
  }

  @GetMapping("/demo/file")
  public String file(@RequestParam String path) throws IOException {
    // Path traversal: user input used in a file path
    return new String(Files.readAllBytes(Paths.get("/var/data/" + path)));
  }
}
