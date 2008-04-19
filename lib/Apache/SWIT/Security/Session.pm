use strict;
use warnings FATAL => 'all';

package Apache::SWIT::Security::Session;
use base 'Apache::SWIT::Session';
use URI;

sub cookie_name { return 'apache_swit_security'; }

my $_sec_man;

sub swit_startup {
	my $class = shift;
	$class->add_class_dbi_var('user', $ENV{AS_SECURITY_USER_CLASS});
	$_sec_man = $ENV{AS_SECURITY_MANAGER}->create;
}

sub authorize {
	my ($self, $ac) = @_;
	return $ac->check_user($self->get_user);
}

sub is_capable {
	my ($self, $cap) = @_;
	return $self->authorize($_sec_man->capability_control($cap));
}

sub is_allowed {
	my ($self, $rel_uri) = @_;
	my $uri = URI->new_abs($rel_uri, $self->request->uri);
	my $ac = $_sec_man->access_control($uri) or return 1;
	return $self->authorize($ac);
}

sub access_handler($$) {
	my ($class, $r) =  @_;
	my $res = $class->SUPER::access_handler($r);
	return $r->pnotes('SWITSession')->is_allowed($r->uri)
		? $res : Apache2::Const::FORBIDDEN();
}

1;
