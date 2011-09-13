<?php
/*
 Plugin Name: Frontend Cookie SSO
 Plugin URI: http://wordpress.org/extend/plugins/frontend-cookie-sso/
 Description: Allow users with a cookie set to comment on your site.
 Author: Thorsten Ott, Automattic
 Version: 0.1
 Author URI: http://hitchhackerguide.com
 */

/**
 * FrontEnd_Cookie_SSO class.
 * 
 */
class FrontEnd_Cookie_SSO {

	private static $__instance = NULL;
	
	private $settings = array();
	private $default_settings = array();
	private $settings_texts = array();
	
	private $plugin_prefix = 'frontendcookiesso_';
	private $plugin_name = 'Frontend Cookie SSO';
	private $settings_page_name ='Frontend Cookie SSO Settings';
	private $dashed_name = 'frontend-cookie-sso';
	private $js_version = '20110905';
	private $css_version = '20110905';
	
	private $is_logged_in = false;
	private $user;
	
	/**
	 * auth_cookie_name
	 * This is the name of the cookie that is used for the validation
	 * It can be altered via the filter hook apply_filters( $this->plugin_prefix . 'auth_cookie_name', $this->auth_cookie_name );
	 *
	 * (default value: 'frontend-sso-cookie')
	 * 
	 * @var string
	 * @access private
	 */
	private $auth_cookie_name = 'frontend-sso-cookie'; 	// feel free to change this to your needs
	
	/**
	 * auth_secret
	 * Default secret thing used for encryptions. You should define FRONT_END_COOKIE_SSO_SECRET in your wp-config.php
	 * 
	 * (default value: 'faa67122369228dd70742cdc935e469e')
	 * 
	 * @var string
	 * @access private
	 */
	private $auth_secret = 'faa67122369228dd70742cdc935e469e';	// this is just a fallback. FRONT_END_COOKIE_SSO_SECRET needs to be set to a real encryption key
	
	/**
	 * __construct function.
	 * 
	 * @access public
	 * @return void
	 */
	public function __construct() {
		global $blog_id;

		if ( NULL <> $this->auth_secret && !defined( 'FRONT_END_COOKIE_SSO_SECRET' ) )
			define( 'FRONT_END_COOKIE_SSO_SECRET', $this->auth_secret );
	}
	
	/**
	 * init function.
	 * 
	 * @access public
	 * @static
	 * @return void
	 */
	public static function init() {
		self::instance()->prepare();
	}
	
	/**
	 * Return Singleton Instance for this class
	 * 
	 * @access public
	 * @static
	 * @return object singleton instance for this class
	 */
	public static function instance() {
		if ( self::$__instance == NULL ) 
			self::$__instance = new FrontEnd_Cookie_SSO;
		return self::$__instance;
	}
	
	/**
	 * prepare settings, variables and hooks
	 * @uses apply_filters() Calls $this->plugin_prefix . 'default_settings' to alter the default plugin settings with (array) $this->default_settings
	 * @uses apply_filters() Calls $this->plugin_prefix . 'settings_texts' to alter the plugin texts with (array) $this->settings_texts.
	 * 
	 * @access public
	 * @return void
	 */
	public function prepare() {
		
		$this->default_settings = (array) apply_filters( $this->plugin_prefix . 'default_settings', array(
			'enable'				=> 0,
			'enable_cookie_encryption' => 1,
			'login_url' => '',
			'logout_url' => '',
			'register_url' => '',
			'try_default_implementation' => 0,
			'set_test_cookie' => 0,
		) );
		
		
		$this->settings_texts = (array) apply_filters( $this->plugin_prefix . 'settings_texts', array(
			'enable'				=> array( 'label' => 'Enable ' . $this->plugin_name, 'desc' => 'Enable this plugin.', 'type' => 'yesno' ),
			'enable_cookie_encryption' => array( 'label' => 'Enable cookie encryption', 'desc' => 'This flag will enable the encryption of the cookie data. This can be slow, so use it only when ', 'type' => 'yesno' ),
			'login_url'			=> array( 'label' => 'Login URL', 'desc' => 'The url to your 3rd party login that would set the cookie.', 'type' => 'text' ),
			'logout_url'			=> array( 'label' => 'Logout URL', 'desc' => 'The url to your 3rd party logout that would unset the cookie', 'type' => 'text' ),
			'register_url'			=> array( 'label' => 'Registration URL', 'desc' => 'The url where users can register with your service', 'type' => 'text' ),
			'try_default_implementation'			=> array( 'label' => 'Try default implementation', 'desc' => 'This setting will add default filters in an attempt to alter your comment form and allow cookie based commenting alongside the regular comments', 'type' => 'yesno' ),
			'set_test_cookie'			=> array( 'label' => 'Set a test cookie', 'desc' => 'This setting will add a test authorization cookie for the whole domain the next time you reload the page', 'type' => 'yesno' ),
		) );
			
		$user_settings = get_option( $this->plugin_prefix . 'settings' );
		if ( false === $user_settings )
			$user_settings = array();
			
		$this->settings = wp_parse_args( $user_settings, $this->default_settings );
		
		// Allow test cookie only if admin domain and front-end domain are the same.
		$host_1 = parse_url( get_home_url(), PHP_URL_HOST );
		$host_2 = parse_url( get_admin_url(), PHP_URL_HOST );
		if ( $host_1 <> $host_2 )
			unset( $this->settings['set_test_cookie'] );
		
		
		if ( 1 == (int) $this->settings['set_test_cookie'] ) {
			$this->set_test_cookie();
		}
		
		
		if ( 1 == (int) $this->settings['enable'] ) {
			// add a batcache variant
			if ( function_exists( 'vary_cache_on_function' ) ) {
				vary_cache_on_function(
					'return isset( $_COOKIE["' . $this->get_auth_cookie_name() . '"]);'
				);
			}
		}
		
		add_action( 'init', array( &$this, 'setup_plugin' ) );
	}
	
	/**
	 * Setup filters and actions, menus, js+css scripts
	 * Validate login
	 *
	 * @access public
	 * @return void
	 */
	public function setup_plugin() {
		add_action( 'admin_init', array( &$this, 'register_setting' ) );
		add_action( 'admin_menu', array( &$this, 'register_settings_page' ) );
		
		if ( file_exists( dirname( __FILE__ ) . "/css/" . $this->dashed_name . ".css" ) )
			wp_enqueue_style( $this->dashed_name, plugins_url( "css/" . $this->dashed_name . ".css", __FILE__ ), $deps = array(), $this->css_version );
		if ( file_exists( dirname( __FILE__ ) . "/js/" . $this->dashed_name . ".js" ) )
			wp_enqueue_script( $this->dashed_name, plugins_url( "js/" . $this->dashed_name . ".js", __FILE__ ), array(), $this->js_version, true );
		
		if ( 1 == $this->settings['enable'] ) {
			if ( is_admin() ) {
				if ( 'faa67122369228dd70742cdc935e469e' == $this->auth_secret || !defined( 'FRONT_END_COOKIE_SSO_SECRET' ) ) {
					add_action( 'admin_notices', array( &$this, 'setup_instructions' ) );
				}
			} else {
				$this->faux_login();
				
				add_filter( 'comment_reply_link', array( $this, 'comment_reply_link' ) );
				add_action( 'pre_comment_on_post', array( $this, 'pre_comment_on_post' ) );
				add_action( 'comment_post', array( $this, 'comment_post_action' ) );
				add_filter( 'comment_form_defaults', array( $this, 'comment_form_defaults' ) );

				if ( 1 == $this->settings['try_default_implementation'] ) {
					add_action( $this->plugin_prefix . 'pre_comment_on_post_logged_in', array( &$this, 'pre_comment_on_post_logged_in' ), 10, 2 );
					add_action( $this->plugin_prefix . 'pre_comment_on_post_logged_out', array( &$this, 'pre_comment_on_post_logged_out' ), 10, 1 );
					add_action( $this->plugin_prefix . 'comment_post_logged_in', array( &$this, 'comment_post_logged_in' ), 10, 2 );
					add_filter( $this->plugin_prefix . 'comment_form_defaults_logged_in', array( &$this, 'comment_form_defaults_logged_in' ), 10, 3 );
					add_filter( $this->plugin_prefix . 'comment_form_defaults_logged_out', array( &$this, 'comment_form_defaults_logged_out' ), 10, 3 );
					add_filter( $this->plugin_prefix . 'comment_reply_link_logged_out', array( &$this, 'comment_reply_link_logged_out' ), 10, 3 );
				}
			}
		}
	}
	
	/**
	 * Print Setup Instructions
	 * 
	 * @access public
	 * @return void
	 */
	public function setup_instructions() {
		echo '<div id="message" class="error"><p>Frontend Cookie SSO needs your attention! You should to add <code>define( \'FRONT_END_COOKIE_SSO_SECRET\', A_SECRET_STRING );</code> to your wp-config.php. <a href="' . menu_page_url( $this->dashed_name, false ) . '">Visit the plugin page for details</a> </p></div>';
	}
	
	/**
	 * Register Settings Page
	 * 
	 * @access public
	 * @return void
	 */
	public function register_settings_page() {
		add_options_page( $this->settings_page_name, $this->plugin_name, 'manage_options', $this->dashed_name, array( &$this, 'settings_page' ) );
	}

	/**
	 * Register Setting
	 * 
	 * @access public
	 * @return void
	 */
	public function register_setting() {
		register_setting( $this->plugin_prefix . 'settings', $this->plugin_prefix . 'settings', array( &$this, 'validate_settings') );
	}
	
	/**
	 * Validate Settings
	 * 
	 * @access public
	 * @param mixed $settings
	 * @return mixed
	 */
	public function validate_settings( $settings ) {
		if ( !empty( $_POST[ $this->dashed_name . '-defaults'] ) ) {
			$settings = $this->default_settings;
			$_REQUEST['_wp_http_referer'] = add_query_arg( 'defaults', 'true', $_REQUEST['_wp_http_referer'] );
		} else {
			
		}
		return $settings;
	}
	
	/**
	 * Print Settings Page
	 * 
	 * @access public
	 * @return void
	 */
	public function settings_page() { 
		if ( !current_user_can( 'manage_options' ) )  {
			wp_die( __( 'You do not permission to access this page' ) );
		}
		?>
		<div class="wrap">
		<?php if ( function_exists('screen_icon') ) screen_icon(); ?>
			<h2><?php echo $this->settings_page_name; ?></h2>
		
			<form method="post" action="options.php">
		
			<?php settings_fields( $this->plugin_prefix . 'settings' ); ?>
		
			<table class="form-table">
				<?php foreach( $this->settings as $setting => $value): ?>
				<tr valign="top">
					<th scope="row"><label for="<?php echo $this->dashed_name . '-' . $setting; ?>"><?php if ( isset( $this->settings_texts[$setting]['label'] ) ) { echo $this->settings_texts[$setting]['label']; } else { echo $setting; } ?></label></th>
					<td>
						<?php switch( $this->settings_texts[$setting]['type'] ):
							case 'yesno': ?>
								<select name="<?php echo $this->plugin_prefix; ?>settings[<?php echo $setting; ?>]" id="<?php echo $this->dashed_name . '-' . $setting; ?>" class="postform">
									<?php 
										$yesno = array( 0 => 'No', 1 => 'Yes' ); 
										foreach ( $yesno as $val => $txt ) {
											echo '<option value="' . esc_attr( $val ) . '"' . selected( $value, $val, false ) . '>' . esc_html( $txt ) . "&nbsp;</option>\n";
										}
									?>
								</select><br />
							<?php break;
							case 'text': ?>
								<div><input type="text" name="<?php echo $this->plugin_prefix; ?>settings[<?php echo $setting; ?>]" id="<?php echo $this->dashed_name . '-' . $setting; ?>" class="postform" value="<?php echo esc_attr( $value ); ?>" /></div>
							<?php break;
							case 'echo': ?>
								<div><span id="<?php echo $this->dashed_name . '-' . $setting; ?>" class="postform"><?php echo esc_attr( $value ); ?></span></div>
							<?php break;
							default: ?>
								<?php echo $this->settings_texts[$setting]['type']; ?>
							<?php break;
						endswitch; ?>
						<?php if ( !empty( $this->settings_texts[$setting]['desc'] ) ) { echo $this->settings_texts[$setting]['desc']; } ?>
					</td>
				</tr>
				<?php endforeach; ?>
				<?php if ( 1 == $this->settings['enable'] ): ?>
					<tr>
						<td colspan="3">
							<p>You enabled frontend-cookie-sso. …. Installation instructions</p>
						</td>
					</tr>
				<?php endif; ?>
			</table>
			
			<p class="submit">
		<?php
				if ( function_exists( 'submit_button' ) ) {
					submit_button( null, 'primary', $this->dashed_name . '-submit', false );
					echo ' ';
					submit_button( 'Reset to Defaults', 'primary', $this->dashed_name . '-defaults', false );
				} else {
					echo '<input type="submit" name="' . $this->dashed_name . '-submit" class="button-primary" value="Save Changes" />' . "\n";
					echo '<input type="submit" name="' . $this->dashed_name . '-defaults" id="' . $this->dashed_name . '-defaults" class="button-primary" value="Reset to Defaults" />' . "\n";
				}
		?>
			</p>
		
			</form>
		</div>
		
		<?php
	}
	
	/**
	 * Get the name of the Authorization Cookie
	 * @uses apply_filters() Calls $this->plugin_prefix . 'auth_cookie_name' to alter the cookie name with (string) $this->auth_cookie_name.
	 * 
	 * @access public
	 * @return string
	 */
	public function get_auth_cookie_name() {
		return apply_filters( $this->plugin_prefix . 'auth_cookie_name', $this->auth_cookie_name );
	}
	
	/**
	 * Tries to decode the given cookie data.
	 * @uses apply_filters() Calls $this->plugin_prefix . 'decode_cookie_data' to allow user defined cookie decoding. Parameters false, (string) $cookie. Function needs to return something other than false to kick in.
	 * 
	 * @access public
	 * @param string $cookie
	 * @return mixed
	 */
	public function decode_cookie( $cookie ) {
		$user_decode = apply_filters( $this->plugin_prefix . 'decode_cookie_data', false, $cookie );
		
		if ( is_wp_error( $user_decode ) || false <> $user_decode ) {
			return $user_encode;
		}
	
		$cookie = $this->decrypt_string( $cookie );
		if ( $_string = base64_decode( $cookie ) ) {
			if ( $_data = json_decode( $_string ) ) {
				if ( isset( $_data->sig ) && isset( $_data->user ) ) {
					if ( $_data->sig == sha1( json_encode( $_data->user ) . FRONT_END_COOKIE_SSO_SECRET ) ) {
						return array( 'sig' => $_data->sig, 'user' => $_data->user );
					}
				}
			}
		}
		return false;
	}
	
	/**
	 * Encode the user data for cookie storage
	 * @uses apply_filters() Calls $this->plugin_prefix . 'default_user_data' to set the default parameters for the user with array( 'author' => '', 'email' => '', 'url' => '' )
	 * @uses apply_filters() Calls $this->plugin_prefix . 'encode_cookie_data' allow user defined cookie encoding. Parameters false, (array) $user_data. Function needs to return something other than false to kick in.
	 * 
	 * @access public
	 * @param array $user_data. (default: array( 'author' => '', 'email' => '', 'url' => '' ) )
	 * @return mixed
	 */
	public function encode_cookie( $user_data = array() ) {
		$user_data_defaults = (array) apply_filters( $this->plugin_prefix . 'default_user_data', array(
			'author'	=> '',
			'email' 	=> '',
			'url'		=> '',
		) );
		
		$user_data = wp_parse_args( $user_data, $user_data_defaults );
		$user_encode = apply_filters( $this->plugin_prefix . 'encode_cookie_data', false, $user_data );
		
		if ( is_wp_error( $user_encode ) || false <> $user_encode ) {
			return $user_encode;
		} else if ( empty( $user_data['author'] ) || empty( $user_data['email'] ) ) {
			return new WP_Error( 'invalid_cookie_data', __( '<strong>ERROR</strong>: author and email cannot be empty.' ) );
		}
		
		$_data = new StdClass;
		$_data->user = $user_data;
		$_data->sig = sha1( json_encode( $_data->user ) . FRONT_END_COOKIE_SSO_SECRET );
		$_data = json_encode( $_data );
		$_string = base64_encode( $_data );
		$_string = $this->encrypt_string( $_string );
		return $_string;
	}

	/**
	 * Validate the cookie based login and set $this->is_logged_in
	 * @uses apply_filters() Calls $this->plugin_prefix . 'validate_user_login' to allow user defined data validation. Use this filter if you want to allow only cookie authorized users to comment or want to block certain users or the like. Parameters (boolean) ( $ext_login || is_user_logged_in() ), (boolean) $ext_login, (array) $this->user, (boolean) is_user_logged_in()
	 * 
	 * @access private
	 * @return void
	 */
	private function faux_login() {
		$ext_login = false;
		if ( isset( $_COOKIE[ $this->get_auth_cookie_name() ] ) ) {
			$cookie = $_COOKIE[ $this->get_auth_cookie_name() ];
			if ( $result = $this->decode_cookie( $cookie ) ) {
				if ( false <> $result ) {
					$this->user = $result['user'];
					$ext_login = true;
				}
			}
		}
		if ( !is_object( $this->user ) )
			$this->user = new StdClass;
			
		$this->is_logged_in = apply_filters( $this->plugin_prefix . 'validate_user_login', ( $ext_login || is_user_logged_in() ), $ext_login, $this->user, is_user_logged_in() );
	}
	
	/**
	 * Create a hash based on the FRONT_END_COOKIE_SSO_SECRET definition
	 * @uses apply_filters() Calls $this->plugin_prefix . 'hash' to allow user defined hash algorithms. Parameter (string) $hash
	 * @access private
	 * @return string
	 */
	private function create_hash() {
		return apply_filters( $this->plugin_prefix . 'hash', substr( sha1( FRONT_END_COOKIE_SSO_SECRET ), 0, 32 ) );
	}
	
	/**
	 * Encrypt the cookie string
	 * @uses apply_filters() Calls $this->plugin_prefix . 'encrypt_string' to allow user defined encryption algorithms. Parameter (boolean) false, (string) $text. Hooked function needs to return something other than false to kick in.
	 * 
	 * @access private
	 * @param string $text
	 * @return string
	 */
	private function encrypt_string( $text ) {
		if ( 1 == $this->settings['enable_cookie_encryption'] ) {
			if ( $user_encryption = apply_filters( $this->plugin_prefix . 'encrypt_string', false, $text ) )
				return $user_encryption;
				
			$salt = $this->create_hash();
			return trim( base64_encode( mcrypt_encrypt( MCRYPT_RIJNDAEL_256, $salt, $text, MCRYPT_MODE_ECB, mcrypt_create_iv( mcrypt_get_iv_size( MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB ), MCRYPT_RAND ) ) ) ); 
		}
		return $text;
	}
	
	/**
	 * Decrypt the cookie string
	 * @uses apply_filters() Calls $this->plugin_prefix . 'decrypt_string' to allow user defined decryption algorithms. Parameter (boolean) false, (string) $text. Hooked function needs to return something other than false to kick in
	 * @access private
	 * @param string $text
	 * @return string
	 */
	private function decrypt_string( $text ) {
		if ( 1 == $this->settings['enable_cookie_encryption'] ) {
			if ( $user_decryption = apply_filters( $this->plugin_prefix . 'decrypt_string', false, $text ) )
				return $user_decryption;
				
			$salt = $this->create_hash();
			return trim( mcrypt_decrypt( MCRYPT_RIJNDAEL_256, $salt, base64_decode( $text ), MCRYPT_MODE_ECB, mcrypt_create_iv( mcrypt_get_iv_size( MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB ), MCRYPT_RAND ) ) ); 
		} 
		return $text;
	}

	/**
	 * Check if a user is logged in via any valid method
	 * 
	 * @access public
	 * @return bool
	 */
	public function is_logged_in() {
		return $this->is_logged_in;
	}
	
	/**
	 * Redirect the user to the defined login url
	 * 
	 * @access public
	 * @param bool $redirect_url. (default: false)
	 * @return void
	 */
	public function login_redirect( $redirect_url = false ) {
		if ( ! $this->is_logged_in() ) {
			wp_redirect( $this->get_login_url( $redirect_url ) );
			exit();
		}
	}

	/**
	 * Return the login url defined in the plugin settings
	 * @uses apply_filters() Calls $this->plugin_prefix . 'get_login_url' to allow overwriting the default url. Parameters (string) url
	 * 
	 * @access public
	 * @param string $redirect_url. (default: false) value of redirect_url parameter appended to url
	 * @return string
	 */
	public function get_login_url( $redirect_url = false ) {
		if ( ! $redirect_url ) {
			$redirect_url = site_url( $_SERVER['REQUEST_URI'] );
		}
		return apply_filters( $this->plugin_prefix . 'get_login_url', $this->settings['login_url'] . '?redirect_url=' . urlencode( $redirect_url ) );
	}
	
	/**
	 * Return the logout url defined in the plugin settings
	 * @uses apply_filters() Calls $this->plugin_prefix . 'get_logout_url' to allow overwriting the default url. Parameters (string) url
	 * @access public
	 * @param string $redirect_url. (default: false) value of redirect_url parameter appended to url
	 * @return string
	 */
	public function get_logout_url( $redirect_url = false ) {
		if ( ! $redirect_url ) {
			$redirect_url = site_url( $_SERVER['REQUEST_URI'] );
		}
		return apply_filters( $this->plugin_prefix . 'get_logout_url', $this->settings['logout_url'] . '?redirect_url=' . urlencode( $redirect_url ) );
	}
	
	/**
	 * Return the registration url defined in the plugin settings
	 * @uses apply_filters() Calls $this->plugin_prefix . 'get_register_url' to allow overwriting the default url. Parameters (string) url
	 * @access public
	 * @param string $redirect_url. (default: false) value of redirect_url parameter appended to url
	 * @return string
	 */
	public function get_register_url( $redirect_url = false ) {
		if ( ! $redirect_url ) {
			$redirect_url = site_url( $_SERVER['REQUEST_URI'] );
		}
		return apply_filters( $this->plugin_prefix . 'get_register_url', $this->settings['register_url'] . '?redirect_url=' . urlencode( $redirect_url ) );
	}
	
	/**
	 * Comment Reply Link. This hooks into comment_reply_link filter and allows altering the reply link based on the users login status
	 * @uses apply_filters() Calls $this->plugin_prefix . 'comment_reply_link_logged_out' to allow an alternative link when logged out. Parameters (string) $html, (string) login_url, (string) register_url
	 * @uses apply_filters() Calls $this->plugin_prefix . 'comment_reply_link_logged_in' to allow an alternative link when logged in. Parameters (string) $html, (array) user, (string) logout_url
	 * @access public
	 * @param string $html
	 * @return string
	 */
	public function comment_reply_link( $html ) {
		if ( ! $this->is_logged_in() ) {
			$html = apply_filters( $this->plugin_prefix . 'comment_reply_link_logged_out', $html, $this->get_login_url(), $this->get_register_url() );
		} else {
			$html = apply_filters( $this->plugin_prefix . 'comment_reply_link_logged_in', $html, $this->user, $this->get_logout_url() );
		}
		return $html;
	}

	/**
	 * Pre Comment On Post. This hooks into pre_comment_on_post and allows alteration of the posted variables before they are processed. In this use case
	 * you can prefill the $_POST with the evalutated user data
	 * @uses do_action() Calls $this->plugin_prefix . 'pre_comment_on_post_logged_in' to perform an action when the user is logged in. Parameters (array) $user, (int) post_id
	 * @uses do_action() Calls $this->plugin_prefix . 'pre_comment_on_post_logged_out' to perform an action when the user is logged out. Parameters (int) post_id
	 * 
	 * @access public
	 * @param int $post_id
	 * @return void
	 */
	public function pre_comment_on_post( $post_id ) {
		if ( $this->is_logged_in() ) {
			do_action( $this->plugin_prefix . 'pre_comment_on_post_logged_in', $this->user, $post_id );
		} else {
			do_action( $this->plugin_prefix . 'pre_comment_on_post_logged_out', $post_id );
		}
	}
	
	/**
	 * Comment Post Action. This hooks into comment_post_action and allows actions to be performed after a comment was processed. In this case this is
	 * mainly useful for updating comment meta or sending a confirmation back to the authenticating system.
	 * @uses do_action() Calls $this->plugin_prefix . 'comment_post_logged_in' to perform an action when the user is logged in. Parameters (int) $comment_id, (array) $user
	 * @uses do_action() Calls $this->plugin_prefix . 'comment_post_logged_out' to perform an action when the user is logged out. Parameters (int) $comment_id
	 * @access public
	 * @param mixed $comment_id
	 * @return void
	 */
	public function comment_post_action($comment_id) {
		if( $this->is_logged_in() ) {
			do_action ( $this->plugin_prefix . 'comment_post_logged_in', $comment_id, $this->user );
		} else {
			do_action ( $this->plugin_prefix . 'comment_post_logged_out', $comment_id );
		}
	}

	/**
	 * Comment Form Defaults. This hooks into the comment_form_defaults filter and lets you alter the fields that will be shown by comment_form()
	 * @uses apply_filters() Calls $this->plugin_prefix . 'comment_form_defaults_logged_in' to alter the fields when the user is logged in. Parameters (array) $defaults, (array) $user, (string) $logout_url
	 * @uses apply_filters() Calls $this->plugin_prefix . 'comment_form_defaults_logged_out' to alter the fields when the user is logged out. Parameters (array) $defaults, (string) $login_url, (string) $registration_url
	 * 
	 * @access public
	 * @param array $defaults
	 * @return array
	 */
	public function comment_form_defaults($defaults) {
		if($this->is_logged_in()) {
			$defaults = apply_filters( $this->plugin_prefix . 'comment_form_defaults_logged_in', $defaults, $this->user, $this->get_logout_url() );
		} else {
			$defaults = apply_filters( $this->plugin_prefix . 'comment_form_defaults_logged_out', $defaults, $this->get_login_url(), $this->get_register_url() );
		}
		return $defaults;
	}

	/**
	 * The comment_reply_link_logged_out function is attached to the comment_reply_link_logged_out hook and will make sure that
	 * logged out users will not get a reply link when try_default_implementation is enabled.
	 * 
	 * @access public
	 * @param string $html
	 * @param string $login_url
	 * @param string $register_url
	 * @return string
	 */
	public function comment_reply_link_logged_out( $html, $login_url, $register_url ) {
		return '';
	}
	
	/**
	 * The pre_comment_on_post_logged_in function is attached to the pre_comment_on_post_logged_in and will prefill the $_POST variables
	 * with the user data provided via the cookie
	 * 
	 * @access public
	 * @param array $user
	 * @param int $post_id
	 * @return void
	 */
	public function pre_comment_on_post_logged_in( $user, $post_id ) {
		if ( isset( $user->author ) )
			$_POST['author'] = esc_attr( $user->author );
		if ( isset( $user->email ) )
			$_POST['email'] = esc_attr( $user->email );
	}
	
	/**
	 * The pre_comment_on_post_logged_out function is attached to pre_comment_on_post_logged_out and ensures that a user who tries commenting 
	 * without being logged-in in term of this plugin will be redirected to the login form
	 *
	 * @access public
	 * @param int $post_id
	 * @return void
	 */
	public function pre_comment_on_post_logged_out( $post_id ) {
		$this->login_redirect();
	}
	
	/**
	 * The comment_post_logged_in function is attached to comment_post_logged_in and updates the comment meta with an external id if it $user->external_id is provided.
	 * 
	 * @access public
	 * @param int $comment_id
	 * @param array $user
	 * @return void
	 */
	public function comment_post_logged_in( $comment_id, $user ) {
		if ( isset( $user->external_id ) )
			update_comment_meta( $comment_id, 'external_id', (int) $user->external_id );
	}
	
	/**
	 * The comment_form_defaults_logged_in function is attached to comment_form_defaults_logged_in and will change the default fields of the comment form for logged in users.
	 * 
	 * @access public
	 * @param array $defaults
	 * @param array $user
	 * @param string $logout_url
	 * @return array
	 */
	public function comment_form_defaults_logged_in( $defaults, $user, $logout_url ) {
		if ( !empty( $user ) ) {
			$defaults['fields'] = array();
			$defaults['title_reply'] = 'Add a Comment';
			$defaults['logged_in_as'] = '<p class="logged-in-as">' . sprintf( __( 'Logged in as %2$s. <a href="%3$s" title="Log out of this account">Log out?</a>' ), $user->author, $logout_url ) . '</p>';
			$defaults['comment_notes_before'] = '<p class="comment-notes">' . __( 'You\'re logged in via external auth' ) . '</p>';
		}
		
		return $defaults;
	}
	
	/**
	 * The comment_form_defaults_logged_out function is attached to comment_form_defaults_logged_out and will change the default fields of the comment form for logged out users.
	 * 
	 * @access public
	 * @param mixed $defaults
	 * @param mixed $login_url
	 * @param mixed $registration_url
	 * @return void
	 */
	public function comment_form_defaults_logged_out( $defaults, $login_url, $registration_url ) {
		$defaults['fields'] = array();
		$defaults['title_reply'] = 'Add a Comment';
		$defaults['comment_field'] = '';
		$defaults['comment_notes_before'] = '<p class="must-log-in">' .  sprintf( __( 'You must be <a href="%s">logged in</a> to post a comment.' ),$login_url ) . ' ' . sprintf( __( 'You can <a href="%s">register here</a>.' ), $registration_url ) . '</p>';
		return $defaults;
	}
	
	/**
	 * This method is used when the set_test_cookie option is triggered and provided a demo cookie. This only works if the admin url is on the same domain as the front-end.
	 * 
	 * @access public
	 * @return void
	 */
	public function set_test_cookie() {
		$user_data = array( 'author' => 'Faux Frontend SSO Test User', 'email' => 'noreply@test.user.me', 'external_id' => 12345678 );
		$cookie = $this->encode_cookie( $user_data );
		$url_split = parse_url( get_home_url() );
		if ( empty( $url_split['path'] ) )
			$url_split['path'] = '/';
		
		setcookie( $this->get_auth_cookie_name(), $cookie, NULL, $url_split['path'] );
		
		$this->settings['set_test_cookie'] = 0;
		update_option( $this->plugin_prefix . 'settings', $this->settings );
		if ( isset( $_COOKIE[$this->get_auth_cookie_name()] ) && $cookie == $_COOKIE[$this->get_auth_cookie_name()] )
			$this->settings_texts['set_test_cookie']['desc'] = 'The ' . $this->get_auth_cookie_name() . ' cookie has been set.';
		else
			$this->settings_texts['set_test_cookie']['desc'] = 'Could not set testcookie ' . $this->get_auth_cookie_name();
	}

}

FrontEnd_Cookie_SSO::init();
