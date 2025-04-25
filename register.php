<?php
require 'db.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email']);
    $password = $_POST['password'];

    // Check if email exists
    $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        echo "Email already exists!";
    } else {
        // Encrypt password
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);

        // Insert user
        $insert = $conn->prepare("INSERT INTO users (email, password) VALUES (?, ?)");
        $insert->bind_param("ss", $email, $hashed_password);
        if ($insert->execute()) {
            echo "Registration successful!";
        } else {
            echo "Error: " . $insert->error;
        }
    }
    $stmt->close();
    $conn->close();
}
?>
