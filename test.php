<?php

require_once "pkg2zip.php";

function addPsmFiles($zip) {
    $zip->AddDirectory("Documents");
    $zip->AddDirectory("System");
    $zip->AddDirectory("Temp");
    $zip->AddFileFromString("RunInSimulator.bat", '"%SCE_PSM_SDK%\target\win32\psm.exe" "%CD%\Application\app.exe"');
}

$f = fopen('../NPNA00143_00.pkg', 'rb');
pkg2zip($f, 'NPNA00143_00', hex2bin('a44a653316667637f413ee3e348ab48e'), 'addPsmFiles');
fclose($f);
