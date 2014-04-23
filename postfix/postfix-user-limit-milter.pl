#!/usr/bin/perl

# Requirements
use POSIX qw(strftime);
use Sendmail::Milter;
use Sys::Syslog;
use DBI;
use strict;

# Config (TODO: Put in config file) ############################################

# Check for number of IPs per user in this timeframe
my $user_ip_timeframe = 120;

# Maximum number of IPs to allow for a user in the above timeframe
my $max_ips_per_timeframe = 4;

# Maximum number of IPs to allow for specific users in the above timeframe.
# This overrides whatever is in $max_user_ips for any users listed in this 
# hash.
my %max_user_ips_custom = ('somebaduser' => 1);

# A custom application to call when a user is blocked. This application or
# script is called with two arguments. The first is the username of the user to
# block, and the second is the number of IPs they have been seen from recently
# (which will either be $max_ips_per_timeframe, or the value for the user set
# in %max_user_ips_custom)
my $custom_reject_action = undef;

# The location of the UNIX socket
my $milter_unix_socket = "/var/run/postfix-user-limit-milter.sock";

# Socket permissions
my $socket_user = "postfix";
my $socket_group = "postfix";
my $socket_mode = "0660";

# Temporary SQLite store filename
my $sqlite_db = "user-limit.db";

################################################################################

my $dbh = undef;

# Called after the user HELO/EHLOing
sub helo_callback
{
	my $ctx = shift;
	my $helo = shift;

	# Get our private data
	my $priv = $ctx->getpriv;
	if ($priv == undef)
	{
		my %temp_arr = ();
		$priv = \%temp_arr;
	}

	# Store all the data
	$priv->{'client_addr'} = $ctx->getsymval("{client_addr}");
	$priv->{'helo'} = $helo;

	# Set the data again
	$ctx->setpriv($priv);

	return SMFIS_CONTINUE;
}

# Called after a MAIL FROM
sub envfrom_callback
{
	my $ctx = shift;
	my $from = shift;

	# Get our private data
	my $priv = $ctx->getpriv;
	if ($priv == undef)
	{
		my %temp_arr = ();
		$priv = \%temp_arr;
	}

	# Store all the data
	my $utc_now = strftime("%s", gmtime);
	my $utc_limit = $utc_now - $user_ip_timeframe;
	$priv->{'auth_authen'} = $ctx->getsymval("{auth_authen}");
	$priv->{'timestamp'} = strftime("%s", gmtime);

	# If nobody authenticated (for example, things in $mynetworks with 
	# permit_mynetworks), we can ifnore all the checks
	if ($priv->{'auth_authen'} eq "")
	{
		return SMFIS_CONTINUE;
	}

	# Insert the tuple of data in to the database
	$dbh->do('BEGIN EXCLUSIVE TRANSACTION') or return SMFIS_CONTINUE;
	$dbh->do("DELETE FROM `connections` WHERE `timestamp` < ?", undef, $utc_limit) or return SMFIS_CONTINUE;
	$dbh->do("INSERT INTO `connections` (`timestamp`, `auth_user`, `conn_source`, `helo`) VALUES (?, ?, ?, ?)", undef, $priv->{'timestamp'}, $priv->{'auth_authen'}, $priv->{'client_addr'}, $priv->{'helo'}) or return SMFIS_CONTINUE;
	$dbh->do('COMMIT TRANSACTION') or return SMFIS_CONTINUE;

	# Get maximum allowed number of IPs per timeframe for this user. Start
	# with the default for all users and then look in the overrides hash
	my $max_user_ips = $max_ips_per_timeframe;
	if (defined($max_user_ips_custom{$priv->{'auth_authen'}}))
	{
		$max_user_ips = $max_user_ips_custom{$priv->{'auth_authen'}};
	}

	# If the maximum IPs for this user is zero, then allow everything
	if ($max_user_ips > 0)
	{
		# Get the number of IPs the user has authenticated from recently
		(my $user_ips) = $dbh->selectrow_array("SELECT COUNT(DISTINCT `conn_source`) FROM `connections` WHERE `auth_user` = ?", undef, $priv->{'auth_authen'});

		# If the user has exceeded their limit, reject the message
		if ($user_ips > $max_user_ips)
		{
			syslog(Sys::Syslog::LOG_WARNING, "Rejecting mail from " . $priv->{'auth_authen'} . ": $user_ips/$max_user_ips IPs in ${user_ip_timeframe}sec(s)\n");

			# If a custom rejection action is specified, call it
			if (defined($custom_reject_action))
			{
				system("$custom_reject_action \"" . $priv->{'auth_authen'} . "\" $max_user_ips");
			}

			return SMFIS_REJECT;
		}
	}
	
	return SMFIS_CONTINUE;
}

# Called on abort on connection close
sub abort_close_callback
{
	my $ctx = shift;

	# Clear the internal pointer (just in case we never get to eom_callback)
	$ctx->setpriv(undef);

	return SMFIS_CONTINUE;
}

# Logs to syslog and then dies
sub syslog_print_and_die
{
	my $err = shift;
	syslog(Sys::Syslog::LOG_CRIT, $err);
	die($err);
}

# Handles SIGINT and SIGTERM
sub signal_handler
{
	syslog(Sys::Syslog::LOG_NOTICE, "Postfix user/IP tracking milter received SIGINT or SIGTERM, exiting");
	closelog();
	if (defined($dbh)) { $dbh->disconnect() };
	exit(0);
}
$SIG{'TERM'} = \&signal_handler;
$SIG{'INT'} = \&signal_handler;

# List of callback functions
my %milter_callbacks =
(
	'helo'    => \&helo_callback,
	'envfrom' => \&envfrom_callback,
	'abort'   => \&abort_close_callback,
);

BEGIN:
{
	# Configure logging
	openlog("postfix-user-limit-milter", "ndelay,pid", Sys::Syslog::LOG_MAIL) or die("Failed to open connect to syslog");

	# Log startup message
	syslog(Sys::Syslog::LOG_NOTICE, "Starting postfix user/IP tracking milter");

	# Set up the connection
	Sendmail::Milter::setconn("unix:$milter_unix_socket") or die();

	# Get UID/GID for given username/group
	my $uid = getpwnam($socket_user);
	if (!defined($uid))
	{
		syslog_print_and_die("Unknown user '$socket_user' for socket_user");
	}
	my $gid = getgrnam($socket_group);
	if (!defined($gid))
	{
		syslog_print_and_die("Unknown group '$socket_group' for socket_group");
	}

	# Validate config
	if (!defined($user_ip_timeframe) or $user_ip_timeframe <= 1)
	{
		syslog_print_and_die("user_ip_timeframe must be greater than 1 second");
	}
	if (!defined($max_ips_per_timeframe) or $max_ips_per_timeframe < 0)
	{
		syslog_print_and_die("max_ips_per_timeframe must be greater than zero");
	}
	for my $user (keys %max_user_ips_custom)
	{
		if ($max_user_ips_custom{$user} < 0)
		{
			syslog_print_and_die("max_user_ips_custom for $user must be greater than zero");
		}
	}

	# Set the permissions on the socket
	chmod oct($socket_mode), $milter_unix_socket;
	chown $uid, $gid, $milter_unix_socket;

	# Initialise SQLite
	$dbh = DBI->connect("dbi:SQLite:dbname=$sqlite_db", "", "") or syslog_print_and_die("Failed to open SQLite database, $sqlite_db");
	my @db_test = $dbh->selectrow_array("SELECT COUNT('name') FROM 'sqlite_master' WHERE type='table' AND name='connections';");
	if ($db_test[0] != 1)
	{
		syslog(Sys::Syslog::LOG_NOTICE, "Temporary SQLite database empty, initialising schema\n");
		$dbh->do("CREATE TABLE 'connections' ('timestamp' DATETIME NOT NULL, 'auth_user' VARCHAR(128), 'conn_source' VARCHAR(512), 'helo' VARCHAR(256))");
		$dbh->do("CREATE INDEX 'connections_timestamp' ON 'connections' ('timestamp')");
		$dbh->do("CREATE INDEX 'connections_auth_user' ON 'connections' ('auth_user')");
		$dbh->do("CREATE INDEX 'connections_conn_source' ON 'connections' ('conn_source')");
	}
	undef @db_test;

	# Register the milter
	Sendmail::Milter::register("postfix-user-limit-milter", \%milter_callbacks, SMFI_CURR_ACTS);

	# Log startup message
	syslog(Sys::Syslog::LOG_NOTICE, "Postfix user/IP tracking milter started");

	# Start the milter
	Sendmail::Milter::main();
}
