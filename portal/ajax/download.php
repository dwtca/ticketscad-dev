<?php
if(empty($_GET)) {
	exit();
	}
require_once('../../../incs/functions.inc.php');

$allowed_dir = realpath(__DIR__ . "/../../files");
$requested = basename($_GET['filename']);
$filepath = realpath($allowed_dir . "/" . $requested);
if ($filepath === false || strpos($filepath, $allowed_dir . DIRECTORY_SEPARATOR) !== 0) {
	http_response_code(403);
	exit('Access denied');
}
$properFilename = basename($_GET['origname']);
header("Content-Disposition: attachment; filename=\"$properFilename\";" );
header("Content-Transfer-Encoding: binary");
header("Pragma: public");
header("Cache-Control: must-revalidate, post-check=0, pre-check=0");
readfile($filepath);
exit();
?>