=== FrontEnd Cookie SSO ===
Contributors: tott, automattic
Tags: sso, sso cookie, single sign on, commenting, comments
Donate link: http://hitchhackerguide.com
Tested up to: 3.1.3
Stable tag: trunk

This plugin lets you implement a cookie based front-end authorization system that can be used (for example) to allow users who are logged in via an system to comment on your site.

== Description ==

BIG WARNING: This is still in early development and needs testing.

This plugin lets you implement a cookie based front-end authorization system that can be used (for example) to allow users who are logged in via an system to comment on your site.

Please see the inline documentation for the various filters this plugin provides to alter it's behaviour.

== Installation ==

* Install either via the WordPress.org plugin directory, or by uploading the files to your server.
* Activate the Plugin and ensure that you enable the feature in the plugins' settings screen
* Add a secret encryption key to your wp-config.php by adding `define( 'FRONT_END_COOKIE_SSO_SECRET', my_secret_string' );`
* Read the inline documentation for ways on how to extend/alter the implementation. Sorry, still working on the documentation.

== Screenshots ==

1. Settings screen to enable/disable various features.

== ChangeLog ==

= Version 0.1 =

* Initial version of this plugin.
