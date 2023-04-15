# Secure login pages (web security project)
## 1) run the following in `phpmyadmin` (after creating the database) :
        `CREATE TABLE users (
    id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);`

## 2) open the `config.php` file and replace the `WebSecurityProject` with your database name

## 3)open `login.php` replace `my-secret-key` in line 8 :
            `$mysecret = "my-secret-key";`
            which is obtained from here : https://www.google.com/recaptcha/admin/create

## 4) open `login.php` replace `your-site-key` in line 162 :
            `<div class="g-recaptcha" data-sitekey="your-site-key"></div>`
            which is obtained from here : https://www.google.com/recaptcha/admin/create

## 5) open `register.php` replace replace `my-secret-key` in line 6 :
            `$mysecret = "my-secret-key";`
            which is obtained from here : https://www.google.com/recaptcha/admin/create

## 6) open `register.php` replace `your-site-key` in line 218 :
            `<div class="g-recaptcha" data-sitekey="your-site-key"></div>`
            which is obtained from here : https://www.google.com/recaptcha/admin/create

## 7) install php on your device

## 8) install composer globally on your device 

## 9) clone the repo and run the following in your terminal (in the folder the contains the files) :
                `composer install `

## 10) google search "localhost" and run it using appache server (XAMP or Ampps or any equevelent)
