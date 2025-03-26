<?php

if (isset($_GET) && isset($_GET['status']))
{
    $status = $_GET['status'];
    $message = $_GET['message'];
    $type = $status == 'success' ? 'success' : 'danger';

    echo "<div class='alert alert-$type' role='alert'>$message</div>";
}