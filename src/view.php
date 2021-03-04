<html>
<head>
<title>w000t</title>

<link type="text/css" rel="stylesheet" href="styles.css"/>

</head>
<body>
<div class="container">
<?php

include 'chicken.php';
error_reporting(E_ALL);
ini_set('display_errors', 1);
if (isset($_GET['xmldoc'])){
	$content = urldecode($_GET['xmldoc']);
	if (preg_match('/(php|zlib|file|http|data|glob|expect):\/\//', $content)){
		echo "Naughty boy";
		header("Location: ");
		die();
		}
		else 
		{ 
			$doc = simplexml_load_string($content, NULL,
				LIBXML_NOENT);  
			echo "If there are no errors on this then XML is parsed";
		}
	}
else {
		echo "cant exploit without userinput lol, and its 'xmldoc' parameter ;) have fun";
}
?>
</div>

</body>
</html>



