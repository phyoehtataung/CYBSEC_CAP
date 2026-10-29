<?php
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET["id"]);
echo $_GET["name"];
system($_GET["cmd"]);
include($_GET["page"]);
$hash = md5($password);
extract($_POST);
$data = unserialize($_GET["data"]);
