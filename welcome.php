<?php
// Initialize the session
session_start();

// Check if the user is logged in, if not then redirect him to login page
if (
    !isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true ||
    !isset($_SESSION["authenticated"]) || $_SESSION["authenticated"] !== true
) {
    if (!isset($_SESSION["signedup"]) || $_SESSION["signedup"] !== true) {
        header("location: login.php");
        exit;
    }
}
$_SESSION["signedup"] = false;
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>Welcome</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        body {
            font: 14px sans-serif;
            text-align: center;
        }
    </style>
</head>

<body>
    <h1 class="my-5">Hi, <b>
            <?php echo htmlspecialchars($_SESSION["username"]); ?>
        </b>. Welcome to our site.</h1>
    <p>
        <a href="reset-password.php" class="btn btn-warning">Reset Your Password</a>
        <a href="logout.php" class="btn btn-danger ml-3">Sign Out of Your Account</a>
    </p>
    <?php
    session_start();
    // header("location: login.php");
    // exit;
    require_once "config.php";
    $sql = "SELECT FA_2_key FROM users WHERE username = ?";
    if ($stmt = mysqli_prepare($link, $sql)) {
        mysqli_stmt_bind_param($stmt, "s", $param_username);
        $param_username = $_SESSION["username"];
        if (mysqli_stmt_execute($stmt)) {
            // Store result
            mysqli_stmt_store_result($stmt);
            if (mysqli_stmt_num_rows($stmt) == 1) {
                mysqli_stmt_bind_result($stmt, $FA_2_key);
                mysqli_stmt_fetch($stmt);
                echo "<p>YOUR SECRET CODE <p>"
                    . $FA_2_key . "</p> </p>";
            }
        }
    } else {
        echo "Oops! Something went wrong. Please try again later.";
    }
    ?>
</body>

</html>