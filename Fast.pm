package MIME::Fast;

use strict;
use Carp;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK $AUTOLOAD);

require Exporter;
require DynaLoader;
require AutoLoader;

@ISA = qw(Exporter DynaLoader);
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
#

$MIME::Fast::GMIME_RECIPIENT_TYPE_TO = 'To';
$MIME::Fast::GMIME_RECIPIENT_TYPE_CC = 'Cc';
$MIME::Fast::GMIME_RECIPIENT_TYPE_BCC = 'Bcc';

@EXPORT = qw(
	$GMIME_RECIPIENT_TYPE_TO
	$GMIME_RECIPIENT_TYPE_CC
	$GMIME_RECIPIENT_TYPE_BCC

	GMIME_LENGTH_ENCODED
	GMIME_LENGTH_CUMULATIVE
	    
	GMIME_PART_ENCODING_DEFAULT
	GMIME_PART_ENCODING_7BIT
	GMIME_PART_ENCODING_8BIT
	GMIME_PART_ENCODING_BASE64
	GMIME_PART_ENCODING_QUOTEDPRINTABLE
	GMIME_PART_NUM_ENCODINGS

	GMIME_RECIPIENT_TYPE_TO
	GMIME_RECIPIENT_TYPE_CC
	GMIME_RECIPIENT_TYPE_BCC

	INTERNET_ADDRESS_NONE
	INTERNET_ADDRESS_NAME
	INTERNET_ADDRESS_GROUP
);
$VERSION = '0.1';

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.  If a constant is not found then control is passed
    # to the AUTOLOAD in AutoLoader.

    my $constname;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    my $val = constant($constname, @_ ? $_[0] : 0);
    if ($! != 0) {
	if ($! =~ /Invalid/) {
	    $AutoLoader::AUTOLOAD = $AUTOLOAD;
	    goto &AutoLoader::AUTOLOAD;
	}
	else {
		croak "Your vendor has not defined MIME::Fast macro $constname";
	}
    }
    eval "sub $AUTOLOAD { $val }";
    goto &$AUTOLOAD;
}

bootstrap MIME::Fast $VERSION;

# Preloaded methods go here.

package MIME::Fast::Message;

sub new {
  my $class = shift;
  my $hash = shift;
  my $self = _new($class);
  return $self;
}

sub sendmail {
  my $msg = shift;
  
  require Mail::Mailer;
  my $mailer = new Mail::Mailer;
  my %headers;

  tie %headers, 'MIME::Fast::Hash::Header', $msg;

  # send headers
  $mailer->open(\%headers);

  my $msg_body = $msg->to_string;
  $msg_body = substr($msg_body, index($msg_body,"\n\n"));
  print $mailer $msg_body;

  $mailer->close();

  untie(%headers);
}

package MIME::Fast::Part;

sub is_multipart {
  my $self = shift;
  return $self->get_content_type->is_type("multipart","*");
}

sub effective_type {
  my $self = shift;
  my $type = $self->get_content_type;
  if (ref $type eq "MIME::Fast::ContentType") {
    $type = $type->to_string;
  }
  return lc($type);
}

sub get_mime_struct {
  my ($part, $maxdepth, $depth) = @_;
  my $ret = "";
  
  $depth = 0 if not defined $depth;
  $maxdepth = 3 if not defined $maxdepth;
  return if ($depth > $maxdepth);
  my $space = "   " x $depth;
  #my $type = $part; # ->get_content_type();
  my $type = $part->get_content_type();
  $ret .= $space . "Content-Type: " . $type->type . "/" . $type->subtype . "\n";
  if ($type->is_type("multipart","*")) {
  #if ($type->type =~ /^multipart/i) {
    my @children = $part->children;
    #print "Child = $children\n";
    $ret .= $space . "Num-parts: " . @children . "\n";
    $ret .= $space . "--\n";
    foreach (@children) {
      #print "$depth Part: $_\n";
      my $str = $_;
      $ret .= &get_mime_struct($str,$maxdepth - 1, $depth + 1);
    }
  } else {
    $ret .= $space . "--\n";
  }
  return $ret;
}

package MIME::Fast;

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__

