<?php 
/**
 * WebMap -> a PHP frontend to nMap
 @author Karl Holz < salamcast _A_ gmail _D_ com >
 @link   http://www.phpclasses.org/package/7550-PHP-Run-nmap-security-audit-tool-from-a-Web-interface.html
 @package WebMap
 @version 2.0
 
 *  
 * This is an update to the code and html with css. 
 * I wanted to to give it an applicaction like feel. 
 * It's now a php class and not a procedural script
 * replaced html tables with div and ul tags, looks right on my iPhone 4
 * uses xhtml output, this will help with applying xslt templates to suck out the selected data and parse it however you want.
 * added get processing, updated the path for nmap to reflect kali linux install location.
 
 * you can use the container on dockerhub
https://hub.docker.com/repository/docker/binholz/webmap
  
 * or just run this from the cmd
[~/WebMap] $ sudo php -S localhost:8080 index.php
 
 * Copyright (c) Feb 2021 Karl Holz <salamcast -at- gmail -dot- com>
 * Copyright (c) 2008 Morgan Collins <morgan -at- morcant.com>

 ported from PHP-NMAP v0.2 http://www.morcant.net/projects/php-nmap

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License
 as published by the Free Software Foundation; either version 2
 of the License, or (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA. 
 */
class WebMap
{
 /**
  * nmap arguments
  * @var type 
  */
    private $args='';
 
 /**
  * boot starp nmap configuration
  * @param type $cmd nmap path
  * @return boolean 
  */
    function __construct($cmd="/usr/bin/nmap")  {
        if (is_file($cmd) && is_executable($cmd)) {
            $this->nmapcmd=$cmd;
        } else {
            echo "nMap Not found!";
            exit();
        }

        // checked for xHTML <input />
       $check="checked='CHECKED'";
       $this->title='WebMap - a PHP frontend to nMap';
        $this->dtstamp=date('YmdHms');
    # defaults
        $this->host='192.168.2.0/24';
        $this->connect=$check;
        $this->tcp=$check;
        $this->method='get';
        /* used with css */
        $this->width="1080px";
        $this->tablebgcolor        = '#e1e1e1'; // Title Background Color
        $this->hostsectioncolor    = '#913a47'; // Host Section Background Color
        $this->scansectioncolor    = '#3c7996'; // Scan Section Background Color
        $this->generalsectioncolor = '#3a914b'; // General Section Background Color
        /* end */
        $clean = array();
        if (is_array($_GET) && count($_GET) > 0) {
            $clean = $_GET;
        } 

        if (count($clean) > 0) {
            foreach($clean as $k => $v) {
                switch ($k) {
                    case "os_detect":
                    case "ident_info":
                    case "fragmentation":
                    case "verbose":
                    case "use_port":
                    case "fast_scan":
                    case "use_decoy":
                    case "use_device":
                    case "dont_resolve":
                    case "udp_scan":
                    case "rpc_scan":
                        $this->$k=$check;
                        break;
                    default:
                        $this->$k=$v;
                }
            }
        }

        if ($this->submit && $this->host) {
            $args = '';
            switch ($this->scan_type) {
                case 'connect': $args .= '-sT '; $this->connect=$check; break;
                case 'syn':     $args .= '-sS '; $this->syn=$check;     break;
                case 'null':    $args .= '-sN '; $this->null=$check;    break;
                case 'fin';     $args .= '-sF '; $this->fin=$check;     break;
                case 'xmas':    $args .= '-sX '; $this->xmas=$check;    break;
                case 'ack':     $args .= '-sA '; $this->ack=$check;     break;
                case 'window':  $args .= '-sW '; $this->window=$check;  break;
                case 'ping';    $args .= '-sP '; $this->ping=$check;    break;
                default:
                    $args.='-sT';
                    $this->connect=$check;
            }
  
            switch ($this->ping_type) {
                case 'tcp':      $args .= '-PT '; $this->tcp=$check;      break;
                case 'tcp_icmp': $args .= '-PB '; $this->tcp_icmp=$check; break;
                case 'icmp':     $args .= '-PI '; $this->icmp=$check;     break;
                case 'none':     $args .= '-P0 '; $this->none=$check;     break;
                default:
                    $args .= '-PB ';
                    $this->tcp_icmp=$check;
            }

            if ($this->os_detect)       $args .= '-O '; 
            if ($this->ident_info)      $args .= '-I '; 
            if ($this->fragmentation)   $args .= '-f '; 
            if ($this->verbose)         $args .= '-v '; 
            if ($this->use_port)        $args .= '-p '.escapeshellarg($this->port_range).' ';
            if ($this->fast_scan)       $args .= '-F '; 
            if ($this->use_decoy)       $args .= '-D '.escapeshellarg($this->decoy_name).' '; 
            if ($this->use_device)      $args .= '-e '.escapeshellarg($this->device_name).' '; 
            if ($this->dont_resolve)    $args .= '-n '; 
            if ($this->udp_scan)        $args .= '-sU ';
            if ($this->rpc_scan)        $args .= '-sR ';
            $this->args=$args .= $this->host_flags.' '.escapeshellarg($this->host);
            return TRUE;
        } else { return FALSE; }
    }
 
    // nMap options
    private $nmap=array();
 /**
  * __get value from nmap array
  * @param type $name
  * @return boolean 
  */
    function __get($name) {
        if(array_key_exists($name, $this->nmap)) {
            return $this->nmap[$name];
        } else {
            return;
        }
    }
 /**
  * __set nmap value to array
  * @param type $name
  * @param type $value 
  */
    function __set($name, $value) { $this->nmap[$name]=$value; }
 /**
  * xHTML header, must run footer to colse the document 
  */
    function header() {
        $a = filter_input(INPUT_SERVER, 'HTTP_ACCEPT');
        if (stristr($a, "application/xhtml+xml")) {
            $this->mime="application/xhtml+xml";
            header("Content-Type: ".  $this->mime);
            print '<?xml version="1.0" encoding="utf-8"?>';
        } else {
            $this->mime="text/html";
            header("Content-Type: ".  $this->mime);
        }
        echo <<<H
<html xmlns="http://www.w3.org/1999/xhtml" >
    <head>
        <title>$this->title</title>
        <meta http-equiv="Content-Type" content="$this->mime; charset=utf-8" />
        <meta http-equiv="Content-Language" content="en-us" />
        <style type="text/css">
  ul {
            list-style-type: none; 
            padding: 3px; 
            margin: 2px; 
  }         
  .tablebgcolor { 
            background-color: $this->tablebgcolor; 
            width: $this->width; 
            padding: 5px;
            text-align: center; 
  }
  div.hostsectioncolor    { 
            background-color: $this->hostsectioncolor;
            width: $this->width; 
            padding: 5px; 
            text-align: center; 
  }
  input.host {
            width: 100px;
  }
  input.button {
            width: 40px;
  }
  div.scansectioncolor    { 
            background-color: $this->scansectioncolor; 
            height: 250px;
            width: 200px; 
            padding: 5px; 
            float: left;
  }
  div.generalsectioncolor { 
            background-color: $this->generalsectioncolor;
            width: $this->width; 
            padding: 5px; 
            height: 250px;
  }
  div.generalsectioncolor div {
            float: right;
  }
  h2 {
            text-align: center; 
  }
  input.button, input.host {
            width: 110px;
  }

  ul {
        width: 250px;
  }
        </style>
    </head>
    <body>
H
    ;
 }
 
    function footer() {
        echo <<<H
    </body>
</html>  
H
        ;
    }
 /**
  * run nMap
  * @param bool $log Logging off by default since windows mostlikely won't have the tee command
  */
    function run_nmap($log=FALSE) {
        if ($this->submit && $this->host) {
            echo '<p id="nmap_cmd">'.$this->nmapcmd.' '.$this->args.'</p>';
            echo '<pre id="nmap_scan">';
            if ($log) {
                system($this->nmapcmd.' '.$this->args.' 2>&1 | tee nmap.'.$this->dtstamp.'.log' );
            } else {
                system($this->nmapcmd.' '.$this->args.' 2>&1' );
            }
            echo '</pre>';
        }
    }
 /**
  * xHTML Form for nMap front end
  * @return string
  */
    function __toString() {
        $page=filter_input(INPUT_SERVER, 'SCRIPT_NAME');
        return <<<HTML
        <form action="$page" method="GET">
            <div class="tablebgcolor" ><h1>$this->title</h1></div>
            <div class="hostsectioncolor">
                <b>Host(s) to scan:</b> 
                <input class="host" type="text" name="host"  value="$this->host" />
                <input class="button" type="submit" name="submit" value="Scan"/>
                <input class="button" type="reset" value="Clear" />
            </div>
            <div  class="scansectioncolor">
                <h2>Scan Options:</h2>
                <ul>
    <li><input type="radio" name="scan_type" value="connect" $this->connect /> connect()</li>
    <li><input type="radio" name="scan_type" value="syn" $this->syn /> SYN Stealth </li>
    <li><input type="radio" name="scan_type" value="null" $this->null /> NULL Scan </li>
    <li><input type="radio" name="scan_type" value="fin" $this->fin /> FIN Scan</li>
    <li><input type="radio" name="scan_type" value="xmas" $this->xmas /> XMAS Scan</li>
    <li><input type="radio" name="scan_type" value="ack" $this->ack /> ACK Scan</li>
    <li><input type="radio" name="scan_type" value="window" $this->window /> Window Scan</li>
                </ul>
            </div> 
            <div  class="generalsectioncolor" >
                <h2>General Options:</h2>
                <div >
                    <ul> 
    <li><input type="checkbox" name="use_port" $this->use_port /> Port Range:<br /> <input class="gen" type="text" name="port_range"   value='$this->port_range' /></li>
    <li><input type="checkbox" name="use_decoy" $this->use_decoy /> Use Decoy(s):<br /> <input class="gen" type="text" name="decoy_name"  value='$this->decoy_name' /></li>
    <li><input type="checkbox" name="use_device" $this->use_device /> Use Device:<br /> <input class="gen" type="text" name="device_name"  value='$this->device_name' /></li>
                    </ul>
                </div>
                <div >
                    <ul>
    <li><input type="checkbox" name="dont_resolve" $this->dont_resolve /> Don't Resolve</li>
    <li><input type="checkbox" name="fast_scan" $this->fast_scan /> Fast Scan</li>
    <li><input type="checkbox" name="verbose" $this->verbose /> Verbose</li>
    <li><input type="checkbox" name="udp_scan" $this->udp_scan /> UDP Scan</li>
    <li><input type="checkbox" name="rpc_scan" $this->rpc_scan /> RPC Scan</li>
    <li><input type="checkbox" name="fragmentation" $this->fragmentation /> Fragmentation</li>
    <li><input type="checkbox" name="os_detect" $this->os_detect /> OS Detection</li>
                    </ul>
                </div>
                <div>
                    <ul >
    <li><b>Ping Type:</b></li>
    <li><input type="radio" name="ping_type" value="tcp" $this->tcp /> TCP Ping</li>
    <li><input type="radio" name="ping_type" value="tcp_icmp" $this->tcp_icmp /> TCP&amp;ICMP Ping</li>
    <li><input type="radio" name="ping_type" value="icmp" $this->icmp /> ICMP Ping</li>
    <li><input type="radio" name="ping_type" value="none" $this->none /> Don't Ping</li>
                    </ul>
                </div>
            </div>
        </form>
HTML
        ;
    }
 

}


?>
