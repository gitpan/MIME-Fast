use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

require 5.8.0; # require perl v5.8.0 or higher

# my $libs = `pkg-config --libs gmime-2.0`;
my $libs = `gmime-config --libs`;
my $vers = `gmime-config --version`;
chomp ($vers);
if ($vers eq "2.0.8") {
	open(VERSION,"> gmime-version.h") || die "Can not open gmime-version.h to write";
	print VERSION "#define GMIME_CHECK_VERSION_2_0_8 1\n";
	print VERSION "#define GMIME_CHECK_VERSION_2_0_9 0\n";
	close(VERSION);
} else {
	die "This version of MIME::Fast module can only run with gmime v2.0.8 (not $vers)\n";
}

WriteMakefile(
    'NAME'		=> 'MIME::Fast',
    'VERSION_FROM'	=> 'Fast.pm', # finds $VERSION
    'PREREQ_PM'		=> {}, # e.g., Module::Name => 1.1
    'LIBS'		=> [$libs], # e.g., '-lm'
    'OPTIMIZE'		=> '-g -ggdb -O',
    'DEFINE'		=> '', # e.g., '-DHAVE_SOMETHING'
    'depend'		=> {
	'Fast.c' => 'Fast-Hash.xs gmime-newfunc.c gmime-newfuncheader.c'
	},
    'clean'             => { FILES => "gmime-version.h" },
    #    'INC'		=> `pkg-config --cflags gmime-2.0` # e.g., '-I/usr/include/other'
    'INC'		=> "-I. " . `gmime-config --cflags`,
);
