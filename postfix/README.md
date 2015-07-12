Postfix Milters
===============

The configuration for both of these milters is contained within the Perl. This
does need to change to be in a config file instead.

These scripts are in use in a production environment, and currently have one
known caveat (which is a bug which needs fixing - see issues).

postfix-log-milter.pl
- Perhaps a bit of a misuse of a milter, this logs messages to a database once
  they've been sent, as I couldn't find anything that would do this very
  nicely (scraping the contents of /var/log/maillog is not nice, and nor is it
  easy to match SpamAssassin scores to messages). Currently this logs to a 
  SQLite database for speed and for less chance of failure. This script logs 
  many headers, including X-Spam-Score which it can then remove before 
  delivery, so that end users don't see what the e-mail matched on.

postfix-user-limit-milter.pl
- This milter keeps track of how what IPs (and HELO strings) a user has logged
  in from recently. If a user logs in from too many IPs in a given timeframe,
  the message can be blocked, and (optionally) a custom action called. The use
  of this script was ideally for authenticated SMTP relays so that if an
  account was compromised and used to send large quantities of spam from many
  compromised machines, this script would prevent them from doing so.

To get either of these milters to work with Postfix, you need to add the 
sockets to your smtpd_milters line in main.cf. You also need to add the
following:

<pre>
# Add client macros for logging
milter_helo_macros = {tls_version} {cipher} {cipher_bits} {cert_subject} {cert_issuer} {client_addr} {client_name} {client_port}
</pre>

You'll also probably want to add this just in case things break (though is
refusing mail worse than not spam-scanning or logging mail?)

<pre>
# Accept mail if SpamAssassin or Log Milter is broken
milter_default_action = accept
</pre>

