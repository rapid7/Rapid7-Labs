---
title: Bludit 3.9.2 remote code execution
author: wchen-r7
score: 2
topic_attacker_value: 5
topic_exploitability: 5
topic_disclosure_date: '2019-09-08T21:15:00'
created: '2019-10-24T04:38:19.269342'
revision_date: '2020-06-03T14:58:35.35096'
assessment_id: 27e118e4-bea7-496d-8dbd-e03ef2c4b6bd
topic_id: c391fe82-5c99-4092-b586-0ff9f6593965
topic_short_id: a91VxoLWn8
topic_slug: bludit-3-9-2-remote-code-execution
akb_topic_url: https://attackerkb.com/topics/a91VxoLWn8/bludit-3-9-2-remote-code-execution
akb_assessment_url: https://attackerkb.com/topics/a91VxoLWn8/bludit-3-9-2-remote-code-execution#27e118e4-bea7-496d-8dbd-e03ef2c4b6bd
author_ratings:
  attacker-value: 5
  confidence-in-ratings: 5
  effort-to-develop-exploit: 2
  exploitability: 5
  urgent-to-patch: 5
  used-successfully: 5
---

# Bludit 3.9.2 remote code execution

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/a91VxoLWn8/bludit-3-9-2-remote-code-execution#27e118e4-bea7-496d-8dbd-e03ef2c4b6bd).*

---

# CVE-2019-16113 Bludit Directory Traversal Vulnerability

## Description

Bludit is a web application written in PHP to build your own website or blog, free and open source. It uses files in JSON format to store the content, so it is configuration-free.

A vulnerability was found in the upload-images.php file, where a remote user could upload a fake image file that is actually a malicious PHP payload, and gain remote code execution.

## Technical Analysis

The vulnerable file (upload-images.php) is written as follows:

```php
<?php defined('BLUDIT') or die('Bludit CMS.');
header('Content-Type: application/json');
/*
| Upload an image to a particular page
|
| @_POST['uuid']	string	Page uuid
|
| @return		array
*/
// $_POST
// ----------------------------------------------------------------------------
$uuid = empty($_POST['uuid']) ? false : $_POST['uuid'];
// ----------------------------------------------------------------------------
// Set upload directory
if ($uuid && IMAGE_RESTRICT) {
	$imageDirectory = PATH_UPLOADS_PAGES.$uuid.DS;
	$thumbnailDirectory = $imageDirectory.'thumbnails'.DS;
	if (!Filesystem::directoryExists($thumbnailDirectory)) {
		Filesystem::mkdir($thumbnailDirectory, true);
	}
} else {
	$imageDirectory = PATH_UPLOADS;
	$thumbnailDirectory = PATH_UPLOADS_THUMBNAILS;
}
$images = array();
foreach ($_FILES['images']['name'] as $uuid=>$filename) {
	// Check for errors
	if ($_FILES['images']['error'][$uuid] != 0) {
		$message = $L->g('Maximum load file size allowed:').' '.ini_get('upload_max_filesize');
		Log::set($message, LOG_TYPE_ERROR);
		ajaxResponse(1, $message);
	}
	// Convert URL characters such as spaces or quotes to characters
	$filename = urldecode($filename);
	// Move from PHP tmp file to Bludit tmp directory
	Filesystem::mv($_FILES['images']['tmp_name'][$uuid], PATH_TMP.$filename);
	// Transform the image and generate the thumbnail
	$image = transformImage(PATH_TMP.$filename, $imageDirectory, $thumbnailDirectory);
	if ($image) {
		$filename = Filesystem::filename($image);
		array_push($images, $filename);
	} else {
		$message = $L->g('File type is not supported. Allowed types:').' '.implode(', ',$GLOBALS['ALLOWED_IMG_EXTENSION']);
		Log::set($message, LOG_TYPE_ERROR);
		ajaxResponse(1, $message);
	}
}
ajaxResponse(0, 'Images uploaded.', array(
	'images'=>$images
));
?>
```

The first thing that happens is that the code retrieves the "uuid" parameter from a POST request:

```php
$uuid = empty($_POST['uuid']) ? false : $_POST['uuid'];
```

The uuid is used as part of the image directory path. If the path doesn't exist, then it will be automatically created:

```php
if ($uuid && IMAGE_RESTRICT) {
	$imageDirectory = PATH_UPLOADS_PAGES.$uuid.DS;
	$thumbnailDirectory = $imageDirectory.'thumbnails'.DS;
	if (!Filesystem::directoryExists($thumbnailDirectory)) {
		Filesystem::mkdir($thumbnailDirectory, true);
	}
```

Next, the code starts uploading the file by accessing the `$_FILES` variables. In here, the content of the uploaded item isn't checked, which means even though the file expects an image file, it doesn't actually have to be. A malicious PHP payload could be uploaded instead:

```php
foreach ($_FILES['images']['name'] as $uuid=>$filename) {
  // ... code ...
```

Finally, the file is moved from PHP's temp file to a custom tmp directory:

```php
Filesystem::mv($_FILES['images']['tmp_name'][$uuid], PATH_TMP.$filename);
```

Even though the image upload is uploaded to Bluedit's tmp directory, you can actually also upload a .htaccess file to allow the PHP payload to be accessed remotely, and gain remote code execution.
