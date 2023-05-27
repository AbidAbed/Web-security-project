<?php
$key;
 $flag;
/* recaptcha code starts here : */
session_start();

$response = $_POST['g-recaptcha-response'] ?? '';
$mysecret = "6LeW-IslAAAAAIqoTp2Qgt-38blZnKik-ooKMGDs";
$url = 'https://www.google.com/recaptcha/api/siteverify';
$data = [
    'secret' => $mysecret,
    'response' => $response
];
$options = [
    'http' => [
        'header' => "Content-type: application/x-www-form-urlencoded\r\n",
        'method' => 'POST',
        'content' => http_build_query($data)
    ]
];
$context = stream_context_create($options);
$result = file_get_contents($url, false, $context);
$jsonArray = json_decode($result, true);
// echo $result;
$key = "success";
$flag = $jsonArray[$key] ?? false;
/* recaptcha code ends here . */
$code_input_err = $code_input = $login_err = "";
if ($_SERVER["REQUEST_METHOD"] == "POST" && $flag) {
    if (empty(trim($_POST["code_input"]))) {
        $code_input_err = "Please enter your code.";
        $login_err = "Please enter your code.";
    } else {
        $code_input = trim($_POST["code_input"]);
    }
    if (empty($code_input_err)) {
        require_once(__DIR__ . '/vendor/autoload.php');
        require_once "config.php";

        $sql = "SELECT FA_2_key,id, username FROM users WHERE username = ?";
        if ($stmt = mysqli_prepare($link, $sql)) {
            mysqli_stmt_bind_param($stmt, "s", $param_username);
            $param_username = $_SESSION["username"];
            if (mysqli_stmt_execute($stmt)) {
                // Store result
                mysqli_stmt_store_result($stmt);
                mysqli_stmt_bind_result($stmt, $FA_2_key, $id, $username);
                mysqli_stmt_fetch($stmt);
                if (mysqli_stmt_num_rows($stmt) == 1) {

                    $google2fa = new \PragmaRX\Google2FA\Google2FA();

                    $valid = $google2fa->verifyKey($FA_2_key, $code_input);

                    if ($valid) {
                        session_start();
                        $_SESSION["loggedin"] = true;
                        $_SESSION["id"] = $id;
                        $_SESSION["username"] = $username;
                        $_SESSION["authenticated"] = true;

                        header("location: welcome.php");
                        exit;
                    } else {
                        $login_err = "Incorrect code";
                    }
                } else {
                    $login_err = "User not found";
                }
            }
            mysqli_stmt_close($stmt);
        }
    }

}  else if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $login_err = "Recaptcha must be solved";
}

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        body {
            font: 14px sans-serif;
        }

        .wrapper {
            width: 360px;
            padding: 20px;
        }
    </style>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
</head>
<body>
    <div class="wrapper">
        <h2>2 FA</h2>
        <p>Please enter the code that is on your google auth app</p>

        

        <?php
        if (!empty($login_err)) {
            echo '<div class="alert alert-danger">' . $login_err . '</div>';
        }
        ?>

        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
            <div class="form-group">
                <label>Code</label>
                <input type="text" name="code_input"
                    class="form-control <?php echo (!empty($code_err)) ? 'is-invalid' : ''; ?>"
                    value="<?php echo $code_input; ?>">
                <span class="invalid-feedback">
                    <?php echo $code_err; ?>
                </span>
            </div>
            <div class="g-recaptcha" data-sitekey="6LeW-IslAAAAAJCUowA8zfm3s1aJBveIOGwbGTDR"></div>
            <div class="form-group">
                <input type="submit" class="btn btn-primary" value="Send">
            </div>
        </form>
    </div>
</body>

</html>
