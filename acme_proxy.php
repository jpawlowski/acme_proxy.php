<?php

/**
 * acme_proxy.php
 *
 * A PHP script to proxy ACME challenge validation
 * requests towards a backend server
 *
 * @author     Julian Pawlowski <julian.pawlowski@gmail.com>
 * @copyright  2018 Julian Pawlowski
 * @license    https://github.com/jpawlowski/acme_proxy.php/blob/master/LICENSE BSD 2-Clause License
 * @link       https://github.com/jpawlowski/acme_proxy.php
 * @version    0.2.2
 *
 *
 * LICENSE:
 *
 * BSD 2-Clause License
 * 
 * Copyright (c) 2018, Julian Pawlowski
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

// default settings
//

$proto = "http://";
$port = 80;
$tls_verify = true;
$fqdn_levels = 5;


// functions
//

function proxyError($type, $detail, $identifier, $code = 503)
{
    // Based on https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md
    // See section "Errors"

    $err = new \stdClass();
    $err->type = "urn:acme-proxy:params:acme:error:".$type;
    $err->detail = $detail;
    if (isset($identifier)) {
        $err->identifier = new \stdClass();
        $err->identifier->type = "http";
        $err->identifier->value = $identifier;
    }
    header("Content-Type: application/problem+json");
    header("Cache-Control: no-store");
    header("X-Powered-By: ACME-Proxy/0.2.2");
    http_response_code($code);
    die(json_encode($err, JSON_PRETTY_PRINT));
}

function proxyGethostbynamel6($hostname)
{
    $result = array();
    $result	= @gethostbynamel($hostname);
    $records6	= @dns_get_record($hostname, DNS_AAAA);
    if (is_array($records6)) {
        foreach ($records6 as $record => $value) {
            $result[] = $value['ipv6'];
        }
    }
    return $result;
}


// main program code
//

list($rpath, $wn, $wnproto, $identifier) = explode("/", $_SERVER['DOCUMENT_URI'], 4);
if ($wn != ".well-known" || $wnproto != "acme-challenge" || !isset($identifier) || $identifier == "") {
    proxyError("malformed", "Missing challenge identifier", null, 405);
}
$uri = $_SERVER['DOCUMENT_URI']."?acme_proxy_request=1";

if (isset($_REQUEST['acme_proxy_request'])) {
    proxyError("serverInternal", "Loop detected", $identifier);
}

$host = $_SERVER['HTTP_HOST'];
if (preg_match("/:\d*$/", $host)) {
    $host = strstr($_SERVER['HTTP_HOST'], ':', true);
}
if (!preg_match("/^(?=^.{1,253}$)(([a-z\d]([a-z\d-]{0,62}[a-z\d])*[\.]){1," . $fqdn_levels . "}[a-z]{1,61})$/", $host)) {
    proxyError("malformed", "Invalid FQDN format in Host request header: $host", $identifier, 405);
}

// add flexibility to forward to port !=80
if (isset($_SERVER['ACME_DST_PORT'])) {
    if (!preg_match("/^\d+$/", $_SERVER['ACME_DST_PORT'])) {
        proxyError("serverInternal", "Invalid destination port", $identifier);
    }

    $port = $_SERVER['ACME_DST_PORT'];
}

// add flexibility to forward requests via TLS
if ($_SERVER['ACME_TLS'] == "true" || $port == 443) {
    $proto = "https://";

    // Implicit port change
    if ($port == 80) {
        $port = 443;
    }

    // add flexibility to disable peer verification
    if ($_SERVER['ACME_TLS_VERIFY'] == "false") {
        $tls_verify = false;
    }
}

if (isset($_SERVER['ACME_DOMAINS'])) {
    $domains = explode(",", $_SERVER['ACME_DOMAINS']);
} else {
    $host_domainname = strstr($_SERVER['SERVER_NAME'], ".");
    if (isset($host_domainname) && $host_domainname != "") {
        $domains[] = strstr($_SERVER['SERVER_NAME'], ".");
    }
}

$valid_domain = false;
if (count($domains) > 0) {
    foreach ($domains as $domain) {
        if (preg_match("/".$domain."$/", $host)) {
            $valid_domain = true;
            break;
        }
    }
}

if ($valid_domain == false) {
    proxyError("connection", "Not serving this domain", $identifier);
}

$host_ipl = proxyGethostbynamel6($host);
$host_ipl_filtered = array();
foreach ($host_ipl as $ip) {
    if (
      $ip == "::1" ||
      $ip == $_SERVER['SERVER_ADDR'] ||
      preg_match("/^127\..*/", $ip)
    ) {
        proxyError("serverInternal", "Validation target blocked", $identifier);
    } elseif (!(
      preg_match("/^169\.254\..*/", $ip) &&
      preg_match("/^fe8.*/", $ip) &&
      preg_match("/^fe9:.*/", $ip) &&
      preg_match("/^fea:.*/", $ip) &&
      preg_match("/^feb:.*/", $ip)
    )) {
        $host_ipl_filtered[] = $ip;
    }
}

if (count($host_ipl_filtered) < 1) {
    proxyError("connection", "DNS error", $identifier);
}

// prepare request
$ch = curl_init($proto . $host . ":" . $port . $uri);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, $tls_verify);
curl_setopt($ch, CURLOPT_HEADER, true);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 10);
curl_setopt($ch, CURLOPT_HTTPHEADER, array(
    "Cache-Control: no-cache"
));
curl_setopt($ch, CURLOPT_RESOLVE, array(
    $host.":".$port.":" . implode(",", $host_ipl_filtered)
));

// send request
$data = curl_exec($ch);
$error = curl_error($ch);
$httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($error) {
    proxyError("connection", "Could not connect to validation target", $identifier);
}

if ($httpcode == 200) {
    list($headers, $body) = explode("\r\n\r\n", $data, 2);
    $headers = explode("\r\n", $headers);
    array_shift($headers); // remove HTTP version

    # Forward all headers from origin
    foreach ($headers as $header) {
        header($header);
    }

    # some privacy for origin server
    header_remove('Date');
    header_remove('Server');

    header("Cache-Control: no-store");
    header("X-Powered-By: ACME-Proxy/0.2.2");
    die($body);
} else {
    proxyError("rejectedIdentifier", "Unknown identifier", $identifier, 403);
}
