use strict;
use warnings FATAL => 'all';

package Apache::SWIT::Security;

our $VERSION = 0.01;

1;

=head1 NAME

Apache::SWIT::Security - security subsystem for Apache::SWIT

=head1 SYNOPSIS

# to install, from command line prompt:
Your-Module $ perl -MApache::SWIT::Security \
		-e 'Apache::SWIT::Security::Maker->install_subsystem("Sec")

=head1 DISCLAIMER
	
This is pre-alpha quality software. Please use it on your own risk.

=head1 DESCRIPTION

This module provides security subsystem for Apache::SWIT based modules.

It does users, roles, url based security etc. For more details look at the
included tests.

=head1 BUGS

Much needed documentation is non-existant at the moment.

=head1 AUTHOR

	Boris Sukholitko
	boriss@gmail.com

=head1 COPYRIGHT

This program is free software; you can redistribute
it and/or modify it under the same terms as Perl itself.

The full text of the license can be found in the
LICENSE file included with this module.


=head1 SEE ALSO

Apache::SWIT

=cut
