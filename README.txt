Here's a basic setup of this php program

// add it into your script with require
require_once 'nmap.cls.php';

// tell it where nmap is located on your system or it will fail
$n=new WebMap('/opt/local/bin/nmap');

// if you want to use xHTML output, call the header
$n->header(); // used for xhtml output

// This prints the xHTML form
echo $n;

// Runs the nMap scan if the options have been passed with the form
// set true to log nmap scan, prints when done
// - tee is used to make log
$n->run_nmap();

//close xhtml output is required if header() was called
$n->footer();


******************

That's it, just not some nmap commands/scans wont run because they require root
So it's up to you to set that up. Running your web server as root on a public system 
would be a bad idea... 

peace