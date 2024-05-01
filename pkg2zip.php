<?php

require_once "support/zip_stream_writer.php";
require_once "pkg.php";


function pkg2zip($r, $name, $rifKey, $addExtraFiles = null) {
    ZipStreamWriter::StartHTTPResponse($name.".zip");

    $zip = new ZipStreamWriter();
	$zip->Init();


    $pkg = Pkg::Read($r, $rifKey);
    foreach ($pkg->Items as $item) {
        $itemName = $item->Name;
        if($itemName == "contents") continue;
        $itemPath = explode("/", $itemName);
        if($itemPath[0] == "contents") {
            array_shift($itemPath);
        }
        $itemName = implode("/", $itemPath);

        if($item->Flags == 4) {
            $zip->AddDirectory($itemName."/", array("last_modified" => time()));
            continue;
        }

        $zip->OpenFile($itemName, array(
            "last_modified" => time(),
            "64bit" => false,
            "unix_attrs" => 0644,
            "extra_fields" => array(),
        ));
        $item->readTo($zip);
        $zip->CloseFile();
        echo $zip->Read();
    }

    if($addExtraFiles) {
        $addExtraFiles($zip);
    }

    $zip->Finalize();
    echo $zip->Read();
}

