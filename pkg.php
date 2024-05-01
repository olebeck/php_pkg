<?php

define('PKG_TYPE_VITA_APP', 0);
define('PKG_TYPE_VITA_DLC', 1);
define('PKG_TYPE_VITA_PATCH', 2);
define('PKG_TYPE_VITA_PSM', 3);
define('PKG_TYPE_PSP', 4);
define('PKG_TYPE_PSX', 5);

function logBytesAsHex($bytes) {
    // Convert the bytes to hexadecimal representation
    $hex = bin2hex($bytes);
    
    // Log the hexadecimal representation
    error_log($hex);
}

class Pkg {
    public $Magic;
    public $Revision;
    public $Type;
    public $ContentID;
    public $ContentType;
    public $Sfo;
    public $Items;

    public function __construct() {
        $this->Magic = "";
        $this->Revision = 0;
        $this->Type = 0;
        $this->ContentID = "";
        $this->ContentType = 0;
        $this->Sfo = null;
        $this->Items = array();
    }

    public static function Read($r, $rifKey) {
        $p = new Pkg();
    
        $headerSize = 232;
        $header = fread($r, $headerSize);
        $p->Magic = substr($header, 0, 4);
        $p->Revision = unpack('n', substr($header, 4, 2))[1];
        $p->Type = unpack('n', substr($header, 6, 2))[1];
    
        $metaOffset = unpack('N', substr($header, 8, 4))[1];
        $metaCount = unpack('N', substr($header, 12, 4))[1];
        $metaSize = unpack('N', substr($header, 16, 4))[1];
    
        $itemCount = unpack('N', substr($header, 20, 4))[1];
        $totalSize = unpack('J', substr($header, 24, 8))[1];
        $encryptedOffset = unpack('J', substr($header, 32, 8))[1];
        $encryptedSize = unpack('J', substr($header, 40, 8))[1];
        $p->ContentID = substr($header, 48, 36);
    
        $digest = substr($header, 96, 16);
        $iv = substr($header, 112, 16);
        $keyType = ord($header[231]) & 7;

        fseek($r, $metaOffset);
        $meta = fread($r, $metaSize);
    
        $itemOffset = 0;
        $itemSize = 0;
        $sfoOffset = 0;
        $sfoSize = 0;
    
        $off = 0;
        for ($i = 0; $i < $metaCount; $i++) {
            $metaElementType = unpack('N', substr($meta, $off, 4))[1];
            $metaElementSize = unpack('N', substr($meta, $off + 4, 4))[1];
    
            switch ($metaElementType) {
                case 2:
                    $p->ContentType = unpack('N', substr($meta, $off + 8, 4))[1];
                    break;
                case 13:
                    $itemOffset = unpack('N', substr($meta, $off + 8, 4))[1];
                    $itemSize = unpack('N', substr($meta, $off + 12, 4))[1];
                    break;
                case 14:
                    $sfoOffset = unpack('N', substr($meta, $off + 8, 4))[1];
                    $sfoSize = unpack('N', substr($meta, $off + 12, 4))[1];
                    break;
            }
    
            $off += $metaElementSize + 8;
        }
    
    
        $pkgType = 0;
        switch ($p->ContentType) {
            case 6:
                $pkgType = PKG_TYPE_PSX;
                break;
            case 7:
            case 0xe:
            case 0xf:
                $pkgType = PKG_TYPE_PSP;
                break;
            case 0x15:
                $pkgType = PKG_TYPE_VITA_APP;
                break;
            case 0x16:
                $pkgType = PKG_TYPE_VITA_DLC;
                break;
            case 0x18:
            case 0x1d:
                $pkgType = PKG_TYPE_VITA_PSM;
                break;
            default:
                throw new Exception("Unknown ContentType " . $p->ContentType);
        }
    
        $mainKey = str_repeat("\x00", 0x10);
        $ps3Key = null;
    
        $key_pkg_ps3_key = "\x2e\x7b\x71\xd7\xc9\xc9\xa1\x4e\xa3\x22\x1f\x18\x88\x28\xb8\xf8";
        $key_pkg_psp_key = "\x07\xf2\xc6\x82\x90\xb5\x0d\x2c\x33\x81\x8d\x70\x9b\x60\xe6\x2b";
        $key_pkg_vita_2 = "\xe3\x1a\x70\xc9\xce\x1d\xd7\x2b\xf3\xc0\x62\x29\x63\xf2\xec\xcb";
        $key_pkg_vita_3 = "\x42\x3a\xca\x3a\x2b\xd5\x64\x9f\x96\x86\xab\xad\x6f\xd8\x80\x1f";
        $key_pkg_vita_4 = "\xaf\x07\xfd\x59\x65\x25\x27\xba\xf1\x33\x89\x66\x8b\x17\xd9\xea";
        switch ($keyType) {
            case 1:
                $mainKey = $key_pkg_psp_key;
                $ps3Key = $key_pkg_ps3_key;
                break;
            case 2:
                $mainKey = openssl_encrypt($iv, 'aes-128-ecb', $key_pkg_vita_2, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
                break;
            case 3:
                $mainKey = openssl_encrypt($iv, 'aes-128-ecb', $key_pkg_vita_3, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
                break;
            case 4:
                $mainKey = openssl_encrypt($iv, 'aes-128-ecb', $key_pkg_vita_4, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
                break;
            default:
                throw new Exception("Unknown key type");
        }
    
        fseek($r, $encryptedOffset+$itemOffset, 0);

        $itemData = openssl_decrypt(fread($r, $itemSize), 'aes-128-ctr', $mainKey, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, incrementIV($iv, intval($itemOffset / 16)));
    
        for ($i = 0; $i < $itemCount; $i++) {
            $off = 32 * $i;
            $item = new Item($r, $encryptedOffset, $rifKey);
    
            $nameOffset = unpack('N', substr($itemData, $off, 4))[1];
            $nameSize = unpack('N', substr($itemData, $off + 4, 4))[1];
            $dataOffset = unpack('J', substr($itemData, $off + 8, 8))[1];
            $dataSize = unpack('J', substr($itemData, $off + 16, 8))[1];
    
            $item->Size = $dataSize;
            $item->Offset = $dataOffset;
            if ($nameSize > 0xffff) {
                throw new Exception("aaaa");
            }
    
            $extra = substr($itemData, $off + 24, 8);
            $item->Flags = ord($extra[3]);
            $pspType = $extra[0];
    
            $item->Name = substr($itemData, $nameOffset, $nameSize);
    
            $item->Key = $mainKey;
            if ($pkgType == PKG_TYPE_PSP || ($pkgType == PKG_TYPE_PSX && $pspType == 0x90)) {
                $item->Key = $mainKey;
            }
            $item->Iv = incrementIV($iv, intval($dataOffset / 16));
    
            $p->Items[] = $item;
        }
    
        return $p;
    }
}

function incrementIV($counter, $increments) {
    // Convert the string counter to an array of bytes
    $counterBytes = unpack('C*', $counter);
    
    $carry = $increments;
    for ($i = 16; $i >= 1 && $carry > 0; $i--) {
        $val = $counterBytes[$i] + $carry;
        $counterBytes[$i] = $val & 0xff;
        $carry = $val >> 8;
    }

    // Pack the incremented bytes back into a string
    $newCounter = call_user_func_array("pack", array_merge(array("C*"), $counterBytes));

    return $newCounter;
}

function IvRoll($location, $original_iv) {
    $packed = pack("P", $location) . pack("P", 0);
    return $original_iv ^ str_pad($packed, 16, "\0", STR_PAD_RIGHT);
}

class Item {
    public $Name;
    public $Flags;
    public $Size;
    public $Offset;
    public $Key;
    public $Iv;

    private $r;
    private $encryptedOffset;
    private $rifKey;

    public function __construct($r, $encryptedOffset, $rifKey) {
        $this->Name = "";
        $this->Flags = 0;
        $this->Size = 0;
        $this->r = $r;
        $this->encryptedOffset = $encryptedOffset;
        $this->rifKey = $rifKey;
    }

    public function readTo($zip) {
        fseek($this->r, $this->Offset + $this->encryptedOffset, 0);
        $chunkSize = 64*1024;

        $bytesRead = 0;
        while($bytesRead < $this->Size) {
            $n = min($chunkSize, $this->Size - $bytesRead);
            $encryptedData = fread($this->r, $n);
            $iv = incrementIV($this->Iv, intval($bytesRead / 16));
            $decryptedData = openssl_decrypt($encryptedData, 'aes-128-ctr', $this->Key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);

            if($bytesRead == 0 && $this->rifKey) {
                $magic = substr($decryptedData, 0, 4);
                if($magic == "PSSE" || $magic == "PSME") {
                    $this->readToPSSE($zip, $decryptedData);
                    return;
                }
            }

            $zip->AppendFileData($decryptedData);
            echo $zip->Read();
            $bytesRead += $n;
        }
    }

    public function readToPSSE($zip, $header) {
        $psm_key = "\x4E\x29\x8B\x40\xF5\x31\xF4\x69\xD2\x1F\x75\xB1\x33\xC3\x07\xBE";
        $psm_iv = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
        $psm_runtime_key = "\xA8\x69\x3C\x4D\xF0\xAE\xED\xBC\x9A\xBF\xD8\x21\x36\x92\x91\x2D";

        $magic = unpack('V', substr($header, 0, 4))[1];
        $version = unpack('V', substr($header, 4, 4))[1];
        $fileSize = unpack('P', substr($header, 8, 8))[1];
        $psseType = unpack('V', substr($header, 16, 4))[1];
        $contentID = substr($header, 20, 0x24);

        $ivKey = $psm_key;
        if($contentID == "IP9100-NPXS10074_00-0000000000000000") {
            $ivKey = $psm_runtime_key;
        }
        $encryptedIV = substr($header, 0x70, 0x10);
        $originalIV = openssl_decrypt($encryptedIV, 'aes-128-cbc', $ivKey, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $psm_iv);

        $totalBlocks = floor($fileSize / 0x8000) + 1;

        fseek($this->r, $this->Offset + $this->encryptedOffset + 0x680, 0);
        $offset = 0x680;
        for($block_id = 0; $block_id < $totalBlocks; $block_id++) {
            $blockSize = 0x8000;
            if($block_id == 0) {
                $blockSize -= 0x680;
            } else if($block_id % 10 == 0) {
                fseek($this->r, 0x400, 1);
                $blockSize -= 0x400;
                $offset += 0x400;
                echo $zip->Read(); // flush every 10 blocks
            }

            if($block_id == $totalBlocks-1) {
                $rd_amt = (($offset - 0x630) - (0x400*floor($offset / 0x80000)));
                $blockSize = $fileSize - $rd_amt;
                if($blockSize == 0) continue;
            }

            $encryptedData = fread($this->r, $blockSize);
            $iv = incrementIV($this->Iv, intval($offset / 16));
            $decryptedData = openssl_decrypt($encryptedData, 'aes-128-ctr', $this->Key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
            $decryptedLength = strlen($decryptedData);
            $decryptedData = str_pad($decryptedData, $decryptedLength + (16 - ($decryptedLength % 16)));
            
            $blockIV = IvRoll($block_id, $originalIV);
            $decryptedBlock = openssl_decrypt($decryptedData, 'aes-128-cbc', $this->rifKey, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $blockIV);
            
            $zip->AppendFileData($decryptedBlock);
            $offset += $blockSize;
        }
    }
}
