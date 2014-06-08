<?php

/**
 * CAS Authentication
 *
 * This plugin augments the RoundCube login page with the ability to authenticate
 * to a CAS server, which enables logging into RoundCube with identities
 * authenticated by the CAS server and acts as a CAS proxy to relay authenticated
 * credentials to the IMAP backend.
 * 
 * The vast majority of this plugin was written by Alex Li. David Warden modified
 * it to be an optional authentication method that can work with stock Roundcube
 * version 0.8.
 *
 * @version 0.8.0
 * @author David Warden (dfwarden@gmail.com)
 * @author Alex Li (li@hcs.harvard.edu)
 * @contributor Julien Gribonvald (julien.gribonvald@recia.fr)
 * @contributor Maxime Bossard (maxime.bossard@recia.fr)
 */

class cas_authn extends rcube_plugin {
    
    private $cas_inited;
    
    /**
     * Initialize plugin
     *
     */
    function init() {
        // initialize plugin fields
        $this->cas_inited = false;
        
        // load plugin configuration
        $this->load_config();
        
        // add application hooks
        $this->add_hook('startup', array($this, 'startup'));
        $this->add_hook('storage_connect', array($this, 'imap_connect'));
        $this->add_hook('smtp_connect', array($this, 'smtp_connect'));
        $this->add_hook('sieverules_connect', array($this, 'sieverules_connect'));
        $this->add_hook('template_object_loginform', array($this, 'add_cas_login_html'));
    }

    /**
     * Handle plugin-specific actions
     * These actions are handled at the startup hook rather than registered as
     * custom actions because the user session does not necessarily exist when
     * these actions need to be handled.
     *
     * @param array $args arguments from rcmail
     * @return array modified arguments
     */
    function startup($args) {
        if ($args['action'] == 'pgtcallback') {
            // Intercept PGT callback action from CAS server
            $this->cas_init();

            // Handle SingleLogout
            phpCAS::handleLogoutRequests(false);

            // Retrieve and store PGT if present
            phpCAS::forceAuthentication();
            
            // end script - once the PGT is stored we don't need to do anything else.
            exit;

        } else if ($args['task'] == 'logout') {
            // Intercept logout action
            // We unfortunately cannot use the logout_after plugin hook because it is
            // executed after session is destroyed
            $this->cas_init();

            // Redirect to CAS logout action if user is logged in to CAS.
            // Also, do the normal Roundcube logout actions.
            if(phpCAS::isSessionAuthenticated()) {
                $RCMAIL = rcmail::get_instance();
                $RCMAIL->logout_actions();
                $RCMAIL->kill_session();
                $RCMAIL->plugins->exec_hook('logout_after', $userdata);
                phpCAS::logout();
                exit;
            }

        } else if ($args['action'] == 'caslogin') {
            // Intercept CAS login
            $this->cas_init();
            
            // Look for _url GET variable and update FixedServiceURL if present to enable deep linking.
            $query = array();
            if ($url = get_input_value('_url', RCUBE_INPUT_GET)) {
                phpCAS::setFixedServiceURL($this->generate_url(array('action' => 'caslogin', '_url' => $url)));
                parse_str($url, $query);
            }

            // Force the user to log in to CAS, using a redirect if necessary.
            phpCAS::forceAuthentication();
            
            // If control reaches this point, user is authenticated to CAS.
            $user = phpCAS::getUser();
            $pass = '';
            // Retrieve credentials, either a Proxy Ticket or 'masteruser' password
            $cfg = rcmail::get_instance()->config->all();
            if ($cfg['cas_proxy']) {
                $_SESSION['cas_pt'][php_uname('n')] = phpCAS::retrievePT($cfg['cas_imap_name'], $err_code, $output);
                $pass = $_SESSION['cas_pt'][php_uname('n')];
            } else {
                $pass = $cfg['cas_imap_password'];
            }
  
            // Do Roundcube login actions
            $RCMAIL = rcmail::get_instance();
            $RCMAIL->login($user, $pass, $RCMAIL->autoselect_host());
            // FIXME: There is a problem somewhere around here that results in 2 PTs being created
            // for the IMAP service. It doesn't seem to break anything if you have IMAP auth caching
            // but it isn't very clean.
            $RCMAIL->session->remove('temp');
            // We don't change the session id which is the CAS login ST.
            $RCMAIL->session->set_auth_cookie();
            rcmail_log_login();
         
            // Allow plugins to control the redirect url after login success
            $redir = $RCMAIL->plugins->exec_hook('login_after', $query + array('_task' => 'mail'));
            unset($redir['abort'], $redir['_err']);
         
            // Send redirect, otherwise control will reach the mail display and fail because the 
            // IMAP session was already started by $RCMAIL->login()
            global $OUTPUT;
            $OUTPUT->redirect($redir);
        }

        return $args;
    }
    
    /**
     * Inject IMAP authentication credentials
     * If you are using this plugin in proxy mode, this will set the password 
     * to be used in RCMAIL->imap_connect to a Proxy Ticket for cas_imap_name.
     * If you are not using this plugin in proxy mode, it will do nothing. 
     * If you are using normal authentication, it will do nothing. 
     *
     * @param array $args arguments from rcmail
     * @return array modified arguments
     */
    function imap_connect($args) {
        $cfg = rcmail::get_instance()->config->all();
        
        // RoundCube is acting as CAS proxy
        if ($cfg['cas_proxy']) {

            // Check expiration of PT caching time
            $ptExpired = false;
            if (time() - $_SESSION['cas_pt_time'][php_uname('n')] > $cfg['cas_imap_pt_expiration_time']) {
                // PT is expired, clear it.
                $_SESSION['cas_pt'][php_uname('n')] = false;
                $ptExpired = true;
            }

            if ($_SESSION['cas_pt'][php_uname('n')] && $cfg['cas_imap_caching'] && $args['attempt'] == 1) {
                // A proxy ticket exists in the PHP session, IMAP auth caching is enabled, and this is the first connection attempt
                $args['pass'] = $_SESSION['cas_pt'][php_uname('n')];
            } else {
                // No proxy tickets have been retrieved, the IMAP server doesn't cache proxy tickets, or the first connection attempt has failed
                $this->cas_init();
                if ($ptExpired) {
                    // Ask the CAS server if user is authenticated, redirect them to CAS if not
                    phpCAS::checkAuthentication();
                }       

                if (phpCAS::isSessionAuthenticated()) {
                    // Retrieve a new proxy ticket and store it in session
                    // FIXME: We probably want some way to update the user's password in the session.
                    $_SESSION['cas_pt'][php_uname('n')] = phpCAS::retrievePT($cfg['cas_imap_name'], $err_code, $output);
                    $_SESSION['cas_pt_time'][php_uname('n')] = time();
                    $args['pass'] = $_SESSION['cas_pt'][php_uname('n')];
                    if ($output) {        
                        error_log("Error while retrieving new PT: " . $output);
                    }
                }
            }
            
            if ($args['attempt'] <= 1) {
                // Enable retry on the first connection attempt only
                $args['retry'] = true;
            }
        }
        return $args;
    }
 
    /**
     * Inject SMTP authentication credentials
     * If you are using this plugin in proxy mode, this will set the password 
     * to be used in RCMAIL->smtp->connect to a new Proxy Ticket for cas_smtp_name.
     * If you are not using this plugin in proxy mode, it will do nothing. 
     * If you are using normal authentication, it will do nothing. 
     *
     * @param array $args arguments from rcmail
     * @return array modified arguments
     */
    function smtp_connect($args) {
        $cfg = rcmail::get_instance()->config->all();
        
        if ($cfg['cas_proxy'] && $args['smtp_user'] && $args['smtp_pass']) {
            // CAS can generate PTs for services and SMTP authn is enabled
            $this->cas_init();

            // Retrieve a new proxy ticket and use it as SMTP password
            // Without forceAuthentication() then retrievePT() fails.
            if (phpCAS::isSessionAuthenticated()) {
                phpCAS::forceAuthentication();
                $args['smtp_pass'] = phpCAS::retrievePT($cfg['cas_smtp_name'], $err_code, $output);
            }
        }
            
        return $args;
    }

    /**
     * Inject Sieve authentication credentials
     * If you are using this plugin in proxy mode, this will set the password
     * to be used in sieverules_connect() to a new Proxy Ticket for opt_cas_imap_name.
     * If you are not using this plugin in proxy mode, it will do nothing.
     * If you are using normal authentication, it will do nothing.
     *
     * @param array $args arguments from rcmail
     * @return array modified arguments
     */
    function sieverules_connect($args) {
        $cfg = rcmail::get_instance()->config->all();

        if ($cfg['opt_cas_proxy']) {
            // CAS can generate PTs
            $this->cas_init();

            // Retrieve a new proxy ticket and use it as the managesieve password
            // Without forceAuthentication() then retrievePT() fails.
            if (phpCAS::isSessionAuthenticated()) {
                phpCAS::forceAuthentication();
                $args['password'] = phpCAS::retrievePT($cfg['cas_imap_name'], $err_code, $output);
            }
        }

        return $args;
    }

    /**
    * Prepend link to CAS login above the Roundcube login form if the user would like to
    * login with CAS.
    */
    function add_cas_login_html($args) {
        $RCMAIL = rcmail::get_instance();
        $this->add_texts('localization');
        $cfg = rcmail::get_instance()->config->all();
    
        if($cfg["cas_force"]) {
            // Force CAS authn, redirect to CAS login Roundcube URL
            global $OUTPUT;
            $OUTPUT->redirect(array('action' => 'caslogin'));
        }

        $caslogin_content = html::div(array(
                                'style' => 'border-bottom: 1px dotted #000; text-align: center; padding-bottom: 1em; margin-bottom: 1em;'),
                                html::a(array(
                                    'href' => $this->generate_url(array('action' => 'caslogin')),
                                    'title' => $this->gettext('casloginbutton')),
                                    $this->gettext('casloginbutton')
                                )
                            );
        $args['content'] = $caslogin_content . $args['content'];
        return $args;
    }

    /**
     * Initialize CAS client
     * 
     */
    private function cas_init() {
        if (!$this->cas_inited) {
            $RCMAIL = rcmail::get_instance();

            $old_session = $_SESSION;
        
            if (!isset($_SESSION['session_inited'])) {    
                // If the session isn't 'inited' by CAS
                // We destroy the session to the CAS client be able to init it
                // FIXME: Not sure if we need to do this.
                session_destroy();
            }

            $cfg = rcmail::get_instance()->config->all();

            require_once('CAS.php');
            
            // Enable CAS debug logging to file, if configured
            if ($cfg['cas_debug_file']) {
                phpCAS::setDebug($cfg['cas_debug_file']);
            }

            // Manage the session only the first time
            phpCAS::client(CAS_VERSION_2_0, $cfg['cas_hostname'], $cfg['cas_port'], $cfg['cas_uri'], !isset($_SESSION['session_inited']));
            if ($cfg['cas_proxy']) {
                // Set URL CAS should call to provide PGT
                phpCAS::setFixedCallbackURL($this->generate_url(array('action' => 'pgtcallback')));
                
                // Set path to store PGTs from CAS
                phpCAS::setPGTStorageFile(session_save_path());
            }

            // SLO callback - FIXME: These callback functions don't exist.
            //phpCAS::setPostAuthenticateCallback("handleCasLogin", $old_session);
            phpCAS::setSingleSignoutCallback(array($this, "handleSingleLogout"));

            // Set service URL for authorization with CAS server
            phpCAS::setFixedServiceURL($this->generate_url(array('action' => 'caslogin')));

            // Set SSL validation for the CAS server
            if ($cfg['cas_validation'] == 'self') {
                phpCAS::setCasServerCert($cfg['cas_cert']);
            } else if ($cfg['cas_validation'] == 'ca') {
                phpCAS::setCasServerCACert($cfg['cas_cert']);
            } else {
                phpCAS::setNoCasServerValidation();
            }

            // set login and logout URLs of the CAS server
            phpCAS::setServerLoginURL($cfg['cas_login_url']);
            phpCAS::setServerLogoutURL($cfg['cas_logout_url']);

            if (!isset($_SESSION['session_inited'])) {    
                // If the session isn't 'inited' by CAS
                // we keep the last session 
                $_SESSION = array_merge($_SESSION, $old_session);
                $_SESSION['session_inited'] = true;
            }

            $this->cas_inited = true;
        }
    }
    
    /**
     * Handle the logout comming from CAS server (globalLogout)
     *
     * @param ticket is the ST name given by CAS for the user when CAS was requested to authenticate on Roundcube.
     */
    function handleSingleLogout($ticket) {
        $RCMAIL = rcmail::get_instance();
        $RCMAIL->session->destroy($ticket);
    }

    /**
     * Build full URLs to this instance of RoundCube for use with CAS servers
     * 
     * @param array $params url parameters as key-value pairs
     * @return string full Roundcube URL
     */
    private function generate_url($params) {
        $s = ($_SERVER['HTTPS'] == 'on') ? 's' : '';
        $protocol = $this->strleft(strtolower($_SERVER['SERVER_PROTOCOL']), '/') . $s;
        $port = (($_SERVER['SERVER_PORT'] == '80' && $_SERVER['HTTPS'] != 'on') ||
                 ($_SERVER['SERVER_PORT'] == '443' && $_SERVER['HTTPS'] == 'on')) ? 
                '' : (':' .$_SERVER['SERVER_PORT']);
        $path = $this->strleft($_SERVER['REQUEST_URI'], '?');
        $parsed_params = '';
        $delm = '?';
        foreach (array_reverse($params) as $key => $val) {
            if (!empty($val)) {
                $parsed_key = $key[0] == '_' ? $key : '_' . $key;
                $parsed_params .= $delm . urlencode($parsed_key) . '=' . urlencode($val);
                $delm = '&';
            }
        }
        $cfg = rcmail::get_instance()->config->all();
        if ( $cfg['cas_webmail_server_name'] ) {
          $serverName = $cfg['cas_webmail_server_name'];
        } else {
          $serverName=$_SERVER['SERVER_NAME'];
        }
        return $protocol . '://' . $serverName . $port . $path . $parsed_params;
    }

    private function strleft($s1, $s2) {
        $length = strpos($s1, $s2);
        if ($length) {
            return substr($s1, 0, $length);
        }
        else {
            return $s1;
        }
    }
}

?>
