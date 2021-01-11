<?php
/*
#############################################################################
#  
#  Developed & Published by:
#  Copyright (c) 2008 by ZULMD DOT COM (IP0445886-X). All right reserved.
#  Hakcipta Terpelihara (c) 2008 oleh ZULMD DOT COM (IP0445886-X)
#   
#  Website : http://www.zulmd.com
#  E-mail : enquiry@zulmd.com
#  Phone : +6013 500 9007 (Zulkifli Mohamed)
#
############################################################################

    Let's Encrypt SSL Automated Renewal Subscription

############################################################################
*/

//==========================================
// SETTINGS
$CPANEL_USER = "CPANEL-USERNAME";
$CPANEL_PWD = 'CPANEL-PASSWORD';
$CPANEL_HOST = "YOUR-CPANEL-HOST";
$CPANEL_2FA_KEY = "YOUR-CPANEL-2FA_KEY";
$TG_API = "TELEGRAM-API-KEY";
$TG_CHATID = "YOUR-TELEGRAM-CHAT-ID";

//==========================================
// PATH
$account_priv_key = 'YOUR-ACCOUNT-PRIVATE-KEY';
$cert_path = "YOUR-CERTIFICATE-SSL-PATH";
$key_path = "YOUR-CERTIFICATE-PRIVATE-KEY-PATH";
$csr_path = "YOUR-CERTIFICATE-CSR-PATH";
$account_key = $key_path . $account_priv_key . '.key';

//==========================================
// GENERAL SETTINGS
error_reporting(E_ALL);
ini_set('max_execution_time', '3000'); // 10 minutes
ini_set('log_errors',1);
ini_set('error_log',dirname(__FILE__).'/ACME.log');

//==========================================
// LIBRARY
require_once('./vendor/autoload.php');
include_once('./cpanelapi.php');
include_once('./acme.php');

// Extract Domain
function extract_domain($text) {
    $text = trim($text, "/");
    $text = strtolower($text);
    $parts = explode("/", $text);
    if (substr_count($parts[0], "http")) {
        $parts[0] = "";
    }
    reset($parts);
    foreach($parts as $key => $val) {
        if (!empty($val)) { $text = $val; break; }
    }
    $parts = explode(".", $text);
    if (empty($parts[2])) {
        return $parts[0].".".$parts[1];
    } else {
        $num_parts = count($parts);
        return $parts[$num_parts-2].".".$parts[$num_parts-1];
    }
}

// Initiate Instance
use TelegramBot\Api\BotApi;
$cp = new cpanelAPI($CPANEL_USER, $CPANEL_PWD, $CPANEL_HOST);
//$cp = new cpanelAPI($CPANEL_USER, $CPANEL_PWD, $CPANEL_HOST, $CPANEL_2FA_KEY); // IF YOU ARE USING 2FA FOR cPanel
$ac = new ACMECert();

// Get SSL Private Keys
$keys = $cp->uapi->SSL->list_keys();
if (is_array($keys->data))
{
    if (count($keys->data) > 0)
    {
        // Sort Private Keys Descending [Z-A]
        usort($keys->data, function($a, $b) {
            return strcasecmp($b->friendly_name, $a->friendly_name);
        });

        $TG_MSG = "";
        foreach ($keys->data as $key)
        {
            $thedomain = strtolower($key->friendly_name);
            if ($thedomain != 'account')
            {
                // Get cert
                $cert = $cp->uapi->SSL->find_certificates_for_key([
                    'id' => $key->id
                ])->data[0];
                $cert_id = $cert->id;

                //==================================
                // Check Certificate Remaining Days
                // If 1 month before expired, request new cert
                //==================================
                $days = $ac->getRemainingDays('file://' . $cert_path . $cert_id . '.crt');
                if ($days > 30) continue;

                //==================================
                // Request New Certificate
                //==================================
                $TG_MSG .= "⚙️ Domain : <b>$thedomain</b>\n";

                // Get CSR
                $csr = $cp->uapi->SSL->find_csrs_for_key(['id' => $key->id])->data[0];
                $csr_id = $csr->id;

                // Show CSR
                $scsr = $cp->uapi->SSL->show_csr(['id' => $csr_id])->data;

                // Delete DNS TXT Records
                $_delete_txts = $cp->api2->ZoneEdit->fetchzone_records([
                    "domain" => extract_domain($thedomain),
                    "type" => "TXT",
                    "name" => "_acme-challenge.".$thedomain."."
                ])->cpanelresult->data;
                if (count($_delete_txts) > 0)
                {
                    foreach($_delete_txts as $_txt)
                    {
                        $cp->api2->ZoneEdit->remove_zone_record([
                            "domain" => extract_domain($thedomain),
                            "line" => $_txt->line
                        ]);
                    }
                }

                // Register/Retrieve Account
                $ac->loadAccountKey('file://'.$account_key);
                $ac->register(true, $scsr->details->emailAddress);

                // List out all domains
                $domains = array();
                foreach ($scsr->details->domains as $domain) {
                    $domains[$domain] = array('challenge'=>'dns-01');
                }

                // Callback functions
                $handler = function($opts) use ($cp, $thedomain)
                {
                    // Add DNS Txt Records
                    $cp->api2->ZoneEdit->add_zone_record([
                        "domain" => extract_domain($thedomain),
                        "name" => $opts['key'] . ".",
                        "type" => "TXT",
                        "txtdata" => $opts['value'],
                        "ttl" => "14400",
                        "class" => "IN"
                    ]);

                    return function($opts) use ($cp, $thedomain)
                    {
                        // Delete DNS TXT Records
                        $txts = $cp->api2->ZoneEdit->fetchzone_records([
                            "domain" => extract_domain($thedomain),
                            "type" => "TXT",
                            "name" => $opts['key'] . "."
                        ])->cpanelresult->data;
                        if (count($txts) > 0)
                        {
                            foreach($txts as $txt)
                            {
                                $cp->api2->ZoneEdit->remove_zone_record([
                                    "domain" => extract_domain($thedomain),
                                    "line" => $txt->line
                                ]);
                            }
                        }
                    };
                };

                // Get Certificate (Use own CSR)
                $new_cert = $ac->getCertificateChain($scsr->csr, $domains, $handler);

                // Delete Old Certificate
                $cp->uapi->SSL->delete_cert(['friendly_name' => strtoupper($thedomain)]);

                // Upload New Certificate
                $upload_cert = $cp->uapi->SSL->upload_cert([
                    'friendly_name' => strtoupper($thedomain),
                    'crt' => $new_cert
                ])->data[0];
                $TG_MSG .= "📜 New Cert ID : <b>" . $upload_cert->id."</b>\n\n";

                // Install Certificate
                if (!empty($upload_cert))
                {
                    $TG_MSG .= "<b>Installation SSL :</b>\n";
                    
                    // Fetch Certificate Data
                    $new_cert_data = $cp->uapi->SSL->fetch_key_and_cabundle_for_certificate([
                        'certificate' => $new_cert
                    ])->data;
                    
                    // Install Main Domain
                    $install_main = $cp->uapi->SSL->install_ssl([
                        'domain' => $thedomain,
                        'cert' => $new_cert_data->crt,
                        'key' => $new_cert_data->key,
                        'cabundle' => $new_cert_data->cab
                    ]);
                    if (empty($install_main->errors)) {
                        $TG_MSG .= "- $thedomain : ✅\n";
                    } else {
                        $TG_MSG .= "- $thedomain : ❌\n";
                    }
                    
                    // Install All Sub Domains
                    $list_domains = $cp->uapi->DomainInfo->list_domains()->data;
                    if (count($list_domains->sub_domains) > 0)
                    {
                        foreach ($list_domains->sub_domains as $subdomain)
                        {
                            if (strpos($subdomain, $thedomain))
                            {
                                $install_sd = $cp->uapi->SSL->install_ssl([
                                    'domain' => $subdomain,
                                    'cert' => $new_cert_data->crt,
                                    'key' => $new_cert_data->key,
                                    'cabundle' => $new_cert_data->cab
                                ]);
                                if (empty($install_sd->errors)) {
                                    $TG_MSG .= "- $subdomain : ✅\n";
                                } else {
                                    $TG_MSG .= "- $subdomain : ❌\n";
                                }
                            }
                        }
                    }
                    
                    // Get Expired Date
                    $ncert = $cp->uapi->SSL->show_cert(['friendly_name' => strtoupper($thedomain)])->data;
                    $TG_MSG .= "\n<b>New Expired Date :</b>\n" . date("d/m/Y h:i:s A", $ncert->details->not_after)."\n\n";
                }
            }
        }
        
        // Finish
        // Send telegram to me :P
        if (!empty($TG_MSG))
        {
            $TG_MSG = "🔰 <b>SSL Certificate Renewal :</b>\n\n".$TG_MSG;
            $bot = new BotApi($TG_API);
            $bot->sendMessage($TG_CHATID, $TG_MSG, 'html', true);
        }
    }
}
?>
