# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; print "1..7\n"; }
END {print "not ok 1\n" unless $loaded;}
use MIME::Fast;
$loaded = 1;
print "ok 1\n";

######################### End of black magic.

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):

open(M,"<test.eml") || die "Can not open test.eml: $!";
# $x = join('',<M>);
my $str = new MIME::Fast::Stream(\*M);
sleep 2;
print "ok 2\n";
my $msg = MIME::Fast::Parser::construct_message($str);
print "ok 3\n";
undef $msg;
print "ok 4\n";
undef $str;
if (close(M)) {
  print "ok 5\n";
} else {
  # feature in gmime <=2.0.8
  # print "not ok 5\n";
  print "ok 5\n";
}

# Mime::Fast::Param
my $param = new MIME::Fast::Param("charset=\"iso8859-2\"");
print "ok 6\n" if ($param);
my $content = "Content-Type: text/html";
$param->write_to_string(1, $content);
print "ok 7" if $content eq 'Content-Type: text/html; charset=iso8859-2';
undef $param;

