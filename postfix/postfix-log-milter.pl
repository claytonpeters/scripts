#!/usr/bin/perl

# Requirements
use POSIX qw(strftime);
use Sendmail::Milter;
use Sys::Syslog;
use DBI;
use strict;

# Config (TODO: Put in config file) ############################################

# The location of the UNIX socket
my $milter_unix_socket = "/var/run/postfix-log-milter.sock";

# The name of the header to process for SpamAssassin score
my $spamassassin_header = "x-spam-status";

# Socket permissions
my $socket_user = "postfix";
my $socket_group = "postfix";
my $socket_mode = "0660";

# Which headers to clear once the message has been processed. This can be used
# so that we log SpamAssassin score from the headers, but then don't pass the
# information on to the recipients
my @clear_headers = ("X-Spam-Status", "X-Spam-Level", "X-Spam-Checker-Version");

# Temporary SQLite store filename
my $sqlite_db = "maillog.db";

################################################################################

my $dbh = undef;

# Called after the user HELO/EHLOing
sub helo_callback
{
	my $ctx = shift;
	my $helo = shift;

	# Get our private data
	my $priv = $ctx->getpriv;
	if (!defined($priv))
	{
		my %temp_arr = ();
		$priv = \%temp_arr;
	}

	# Store all the data
	$priv->{'client_addr'} = $ctx->getsymval("{client_addr}");
	$priv->{'client_port'} = $ctx->getsymval("{client_port}");
	$priv->{'client_name'} = $ctx->getsymval("{client_name}");
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
	if (!defined($priv))
	{
		my %temp_arr = ();
		$priv = \%temp_arr;
	}

	# Store all the data
	$priv->{'auth_type'} = $ctx->getsymval("{auth_type}");
	$priv->{'auth_authen'} = $ctx->getsymval("{auth_authen}");
	$priv->{'env_from'} = $from;

	# Set the data again
	$ctx->setpriv($priv);

	return SMFIS_CONTINUE;
}

# Called after each RCPT TO
sub envrcpt_callback
{
	my $ctx = shift;
	my $rcpt = shift;

	# Get our private data
	my $priv = $ctx->getpriv;
	if (!defined($priv))
	{
		my %temp_arr = ();
		$priv = \%temp_arr;
	}

	# Store the queue ID
	$priv->{'queue_id'} = $ctx->getsymval("i");

	# Create the recipient field or add on a recipeint
	if (!defined($priv->{'env_to'}))
	{
		$priv->{'env_to'} = $rcpt;
		$priv->{'num_recipients'} = 1;
	}
	else
	{
		$priv->{'env_to'} = $priv->{'env_to'} . ", $rcpt";
		$priv->{'num_recipients'}++;
	}

	# Set the data again
	$ctx->setpriv($priv);

	return SMFIS_CONTINUE;
}

# Called after each header in the message
sub header_callback
{
	my $ctx = shift;
	my $header = shift;
	my $value = shift;

	# Get our private data
	my $priv = $ctx->getpriv;
	if (!defined($priv))
	{
		my %temp_arr = ();
		$priv = \%temp_arr;
	}

	# Check the header name and store appropriately
	if ($header =~ /^subject$/i)
	{
		$priv->{'hdr_subject'} = $value;
	}
	elsif ($header =~ /^from$/i)
	{
		$priv->{'hdr_from'} = $value;
	}
	elsif ($header =~ /^to$/i)
	{
		$priv->{'hdr_to'} = $value;
	}
	elsif ($header =~ /^$spamassassin_header$/i)
	{
		# Join multi-line header value
		$value =~ s/\n\s+/ /mg;

		$priv->{'spam_status'} = $value;
		if ($value =~ /^yes,$/i)
		{
			$priv->{'spam_result'} = 1;
		}
		else
		{
			$priv->{'spam_result'} = 0;
		}
		my @matches = ($value =~ m/(yes|no),\s+score=([0-9]+\.[0-9]+)/i);
		$priv->{'spam_score'} = $matches[1];
	}

	# Set the data again
	$ctx->setpriv($priv);

	return SMFIS_CONTINUE;
}

# Called after each body junk (seemingly about 64kb)
sub body_callback
{
	my $ctx = shift;
	my $body = shift;
	my $len = shift;

	# Get our private data
	my $priv = $ctx->getpriv;
	if (!defined($priv))
	{
		my %temp_arr = ();
		$priv = \%temp_arr;
	}

	# Add on the body chunk size
	if (!defined($priv->{'body_size'}))
	{
		$priv->{'body_size'} = $len;
	}
	else
	{
		$priv->{'body_size'} = $priv->{'body_size'} + $len;
	}

	# Set the data again
	$ctx->setpriv($priv);

	return SMFIS_CONTINUE;
}

# Called after the end of the message
sub eom_callback
{
	my $ctx = shift;

	# Get our private data
	my $priv = $ctx->getpriv;
	if (!defined($priv))
	{
		my %temp_arr = ();
		$priv = \%temp_arr;
	}

	# Store the data
	$priv->{'timestamp'} = strftime("%s", gmtime);

	# Might be multiple threads/processes writing to the database, so lock around it
	$dbh->do('BEGIN EXCLUSIVE TRANSACTION') or return SMFIS_CONTINUE;

	# Prepare to insert
	my $sth = $dbh->prepare("INSERT INTO 'messages' ('id', 'timestamp', 'helo', 'auth_method', 'auth_user', 'conn_source', 'env_from', 'env_to', 'body_size', 'num_recipients', 'hdr_from', 'hdr_to', 'hdr_subject', 'spam_result', 'spam_score', 'spam_status') VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)") or return SMFIS_CONTINUE;
	$sth->bind_param(1,  $priv->{'queue_id'})        or return SMFIS_CONTINUE;
	$sth->bind_param(2,  $priv->{'timestamp'})       or return SMFIS_CONTINUE;
	$sth->bind_param(3,  $priv->{'helo'})            or return SMFIS_CONTINUE;
	$sth->bind_param(4,  $priv->{'auth_type'})       or return SMFIS_CONTINUE;
	$sth->bind_param(5,  $priv->{'auth_authen'})     or return SMFIS_CONTINUE;
	$sth->bind_param(6,  $priv->{'client_name'} . '[' . $priv->{'client_addr'} . ']:' . $priv->{'client_port'}) or return SMFIS_CONTINUE;
	$sth->bind_param(7,  $priv->{'env_from'})        or return SMFIS_CONTINUE;
	$sth->bind_param(8,  $priv->{'env_to'})          or return SMFIS_CONTINUE;
	$sth->bind_param(9,  $priv->{'body_size'})       or return SMFIS_CONTINUE;
	$sth->bind_param(10, $priv->{'num_recipients'})  or return SMFIS_CONTINUE;
	$sth->bind_param(11, $priv->{'hdr_from'})        or return SMFIS_CONTINUE;
	$sth->bind_param(12, $priv->{'hdr_to'})          or return SMFIS_CONTINUE;
	$sth->bind_param(13, $priv->{'hdr_subject'})     or return SMFIS_CONTINUE;
	$sth->bind_param(14, $priv->{'spam_result'})     or return SMFIS_CONTINUE;
	$sth->bind_param(15, $priv->{'spam_score'})      or return SMFIS_CONTINUE;
	$sth->bind_param(16, $priv->{'spam_status'})     or return SMFIS_CONTINUE;

	# Do the insert
	$sth->execute() or return SMFIS_CONTINUE;
	$dbh->do('COMMIT TRANSACTION') or return SMFIS_CONTINUE;

	# Log to syslog 
	syslog(Sys::Syslog::LOG_INFO, "Logged message " . $priv->{'queue_id'} . " to database");
	
	# Clear the headers that we want to clear
	for my $header (@clear_headers)
	{
		$ctx->chgheader($header, 0, "");
	}

	# Clear the internal pointer
	$ctx->setpriv(undef);

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
	syslog(Sys::Syslog::LOG_NOTICE, "Postfix logging milter received SIGINT or SIGTERM, exiting");
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
	'envrcpt' => \&envrcpt_callback,
	'header'  => \&header_callback,
	'body'    => \&body_callback,
	'eom'     => \&eom_callback,
	'abort'   => \&abort_close_callback,
	'close'   => \&abort_close_callback,
);

BEGIN:
{
	# Configure logging
	openlog("postfix-log-milter", "ndelay,pid", Sys::Syslog::LOG_MAIL) or die("Failed to open connect to syslog");

	# Log startup message
	syslog(Sys::Syslog::LOG_NOTICE, "Starting postfix logging milter");

	# Set up the connection
	Sendmail::Milter::setconn("unix:$milter_unix_socket") or syslog_print_and_die("Failed to open unix socket, $milter_unix_socket");

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

	# Set the permissions on the socket
	chmod oct($socket_mode), $milter_unix_socket;
	chown $uid, $gid, $milter_unix_socket;

	# Initialise SQLite
	$dbh = DBI->connect("dbi:SQLite:dbname=$sqlite_db", "", "") or syslog_print_and_die("Failed to open SQLite database, $sqlite_db");
	my @db_test = $dbh->selectrow_array("SELECT COUNT('name') FROM 'sqlite_master' WHERE type='table' AND name='messages';");
	if ($db_test[0] != 1)
	{
		syslog(Sys::Syslog::LOG_NOTICE, "Temporary SQLite database empty, initialising schema\n");
		$dbh->do("CREATE TABLE messages ('id' VARCHAR(14) NOT NULL, 'timestamp' DATETIME NOT NULL, 'helo' VARCHAR(256), 'auth_method' VARCHAR(16), 'auth_user' VARCHAR(128), 'conn_source' VARCHAR(512), 'env_from' VARCHAR(256), 'env_to' VARCHAR(1024), 'body_size' INT, 'num_recipients' SMALLINT, 'hdr_from' VARCHAR(256), 'hdr_to' VARCHAR(1024), 'hdr_subject' VARCHAR(512), 'spam_result' BOOLEAN, 'spam_score' DECIMAL(5,1), 'spam_status' TEXT, PRIMARY KEY ('id'))");
		$dbh->do("CREATE INDEX 'messages_helo' ON 'messages' ('helo')");
		$dbh->do("CREATE INDEX 'messages_auth_user' ON 'messages' ('auth_user')");
		$dbh->do("CREATE INDEX 'messages_env_from' ON 'messages' ('env_from')");
		$dbh->do("CREATE INDEX 'messages_env_to' ON 'messages' ('env_to')");
		$dbh->do("CREATE INDEX 'messages_hdr_from' ON 'messages' ('hdr_from')");
		$dbh->do("CREATE INDEX 'messages_hdr_to' ON 'messages' ('hdr_to')");
	}
	undef @db_test;

	# Register the milter
	Sendmail::Milter::register("postfix-log-milter", \%milter_callbacks, SMFI_CURR_ACTS);

	# Log startup message
	syslog(Sys::Syslog::LOG_NOTICE, "Postfix logging milter started");

	# Start the milter
	Sendmail::Milter::main();
}
