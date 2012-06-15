<?php

/*
WebMap Class demo
 */
require_once 'nmap.cls.php';
$n=new WebMap('/opt/local/bin/nmap');
$n->header(); // used for xhtml output
//print xhtml form
echo $n;
//set true to log nmap scan, prints when done
$n->run_nmap();
//close xhtml output
$n->footer();
?>
