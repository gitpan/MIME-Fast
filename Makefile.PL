use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
my $libs = `gmime-config --libs`;
WriteMakefile(
    'NAME'		=> 'MIME::Fast',
    'VERSION_FROM'	=> 'Fast.pm', # finds $VERSION
    'PREREQ_PM'		=> {}, # e.g., Module::Name => 1.1
    'LIBS'		=> [$libs], # e.g., '-lm'
    'OPTIMIZE'		=> '-O',
    'DEFINE'		=> '', # e.g., '-DHAVE_SOMETHING'
    'CC'		=> 'gcc',
    'INC'		=> `gmime-config --cflags`, # e.g., '-I/usr/include/other'
);
