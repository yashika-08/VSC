<?php
// test/samples/vulnerable-page.php
// Sample file with intentional PHP vulnerabilities for testing Sentinel-VSC

// ❌ VULNERABLE: SQL Injection — mysql_query with $_GET (sqli-007)
function getUser() {
    $id = $_GET['id'];
    $result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id']);
    return mysqli_fetch_assoc($result);
}

// ❌ VULNERABLE: XSS — echo unsanitized superglobal (xss-006)
function renderGreeting() {
    echo "<h1>Hello, " . $_GET['name'] . "</h1>";
    echo "Welcome back, " . $_POST['username'];
}

// ❌ VULNERABLE: Command Injection — shell_exec with user input (cmdi-004)
function convertImage() {
    $filename = $_POST['filename'];
    shell_exec("convert " . $_POST['filename'] . " -resize 200x200 output.jpg");
}

// ❌ VULNERABLE: Insecure Deserialization — unserialize (deser-004)
function loadSession() {
    $data = unserialize($_COOKIE['session_data']);
    return $data;
}

// ❌ VULNERABLE: Weak hash — md5 password (auth-004)
function hashPassword($password) {
    return md5($password);
}

// ❌ VULNERABLE: Hardcoded credentials (auth-003)
$db_password = "SuperSecret123!";
$api_key = "sk-live-XXXXXXXXXXXXXXXX";
?>
