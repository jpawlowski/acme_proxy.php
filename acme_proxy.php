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
 * @version    0.1
 */

// default settings
//

$proto = "http://";
$host = strstr($_SERVER['HTTP_HOST'], ':', true);
$uri = $_SERVER['DOCUMENT_URI']."?acme_proxy_request=1";
$port = 80;
$tls_verify = true;
$fqdn_levels = 5;


// functions
//

function proxyError($type, $detail, $identifier, $code = 503)
{
    // Based on https://github.com/ietf-wg-acme/acme/blob/master/draft-ietf-acme-acme.md
    // See section "Errors"

    $err->type = "urn:acme-proxy:params:acme:error:".$type;
    $err->detail = $detail;
    if (isset($identifier)) {
        $err->identifier->type = "http";
        $err->identifier->value = $identifier;
    }
    header("Cache-Control: no-store");
    header("X-Powered-By: ACME-Proxy/0.1");
    http_response_code($code);
    die(json_encode($err, JSON_PRETTY_PRINT));
}

function proxyGethostbynamel6($hostname)
{
    $result = array();
    $result	= gethostbynamel($hostname);
    $records6	= dns_get_record($hostname, DNS_AAAA);
    foreach ($records6 as $record => $value) {
        $result[] = $value['ipv6'];
    }
    return $result;
}


// main program code
//

list($rpath, $wn, $wnproto, $identifier) = explode("/", $uri, 4);
if ($wn != ".well-known" || $wnproto != "acme-challenge" || !isset($identifier) || $identifier == "") {
    proxyError("malformed", "Missing challenge identifier", null, 405);
}

if (isset($_REQUEST['acme_proxy_request'])) {
    proxyError("serverInternal", "Loop detected", $identifier);
}

if (!preg_match("/^(?=^.{1,253}$)(([a-z\d]([a-z\d-]{0,62}[a-z\d])*[\.]){1," . $fqdn_levels . "}[a-z]{1,61})$/", $host)) {
    proxyError("malformed", "Invalid FQDN format in Host request header", $identifier, 405);
}

// add flexibility to forward to port !=80
if (isset($_REQUEST['acme_dst_port'])) {
    if (!preg_match("/^\d+$/", $_REQUEST['acme_dst_port'])) {
        proxyError("malformed", "Invalid destination port", $identifier, 405);
    }

    $port = $_REQUEST['acme_dst_port'];
}

// add flexibility to forward requests via TLS
if ($_REQUEST['acme_tls'] == "true" || $port == 443) {
    $proto = "https://";

    // Implicit port change
    if ($port == 80) {
        $port = 443;
    }

    // add flexibility to disable peer verification
    if ($_REQUEST['acme_tls_verify'] == "false") {
        $tls_verify = false;
    }
}

$host_ipl = proxyGethostbynamel6($host);
$host_ipl_filtered = array();
foreach ($host_ipl as $ip) {
    if (
      $ip == "::1" ||
      preg_match("/^127\..*/", $ip)
    ) {
        proxyError("serverInternal", "Validation target blocked", $identifier);
    } elseif (!(
      preg_match("/^169\.254\..*/", $ip) &&
      preg_match("/^fe80:.*/", $ip)
    )) {
        $host_ipl_filtered[] = $ip;
    }
}

if (count($host_ipl_filtered) < 1) {
    proxyError("serverInternal", "DNS error", $identifier);
}

// prepare request
$ch = curl_init($proto . $host . ":" . $port . $uri);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, $tls_verify);
curl_setopt($ch, CURLOPT_HEADER, true);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 10);
curl_setopt($ch, CURLOPT_HTTPHEADER, array(
    'Cache-Control: no-cache'
));
curl_setopt($ch, CURLOPT_RESOLVE, "$host:$port:" . implode(",", $host_ipl_filtered));

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
    header("X-Powered-By: ACME-Proxy/0.1");
    die($body);
} else {
    proxyError("rejectedIdentifier", "Unknown identifier", $identifier, 403);
}
